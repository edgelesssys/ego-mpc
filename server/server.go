/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: MPL-2.0
*/

package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/edgelesssys/ego-mpc/db"
	"github.com/edgelesssys/ego-mpc/internal/constants"
	_ "github.com/edgelesssys/ego-mpc/internal/ignoresigsys" // don't panic on EGo API calls outside the EGo runtime on macOS
	"github.com/edgelesssys/ego/enclave"
)

type EnclaveServer struct {
	db     *serverDB
	onInit func(*x509.Certificate) error
	mux    *http.ServeMux
	report []byte

	mut sync.Mutex
	// if these are set, the certificate hasn't been stored to the db yet
	appCertificate []byte
	appPrivKey     crypto.PrivateKey
}

// New creates a new EnclaveServer. api will be served at /api/.
// Optionally provide onInit, which will be called on /init.
func New(db *db.EncryptedDB, api http.HandlerFunc, onInit func(owner *x509.Certificate) error) *EnclaveServer {
	s := &EnclaveServer{
		db:     &serverDB{db},
		onInit: onInit,
		mux:    http.NewServeMux(),
	}
	s.mux.HandleFunc("/api/", s.middleware(api))
	s.mux.HandleFunc("/platform/attest", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(s.report) })
	s.mux.HandleFunc("/platform/init", s.handleInit)
	s.mux.HandleFunc("/platform/owner", s.handleOwner)
	return s
}

// Run runs the server on the given port.
func (s *EnclaveServer) Run(port string) {
	cert, key, err := s.getOrCreateCertificate()
	if err != nil {
		log.Fatalln("Failed to create server certificate:", err)
	}
	certHash := sha256.Sum256(cert)
	s.report, err = enclave.GetRemoteReport(certHash[:])
	if err != nil {
		log.Println("ERROR: Failed to get remote report:", err)
		log.Print("ERROR: Enclave won't be verifiable.")
	}

	server := http.Server{
		Addr:    ":" + port,
		Handler: s.mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{cert},
					PrivateKey:  key,
				},
			},
			ClientAuth: tls.RequestClientCert,
		},
	}
	log.Println("Listening on", server.Addr, "...")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func (s *EnclaveServer) isInitialized() bool {
	return s.appCertificate == nil
}

func (s *EnclaveServer) middleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mut.Lock()
		initialized := s.isInitialized()
		s.mut.Unlock()
		if !initialized {
			http.NotFound(w, r)
			return
		}
		if err := s.auth(r); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		next(w, r)
	})
}

// auth checks if the client sent a well-formed certificate.
// Verifying the certificate and enforcing permissions is the responsibility of the invoked API.
func (s *EnclaveServer) auth(r *http.Request) error {
	switch len(r.TLS.PeerCertificates) {
	case 0:
		return errors.New("no client certificate provided")
	case 1:
	default:
		return errors.New("more than one client certificate provided")
	}
	cert := r.TLS.PeerCertificates[0]

	// verify self-signed cert to ensure it's well-formed
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	_, err := cert.Verify(x509.VerifyOptions{Roots: roots})

	return err
}

func (s *EnclaveServer) handleInit(w http.ResponseWriter, r *http.Request) {
	s.mut.Lock()
	defer s.mut.Unlock()

	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := s.auth(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if s.isInitialized() {
		http.Error(w, "already initialized", http.StatusGone)
		return
	}
	ownerCert := r.TLS.PeerCertificates[0]
	if s.onInit != nil {
		if err := s.onInit(ownerCert); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := s.db.setConfig(s.appCertificate, s.appPrivKey, ownerCert.Raw); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.appCertificate = nil
	s.appPrivKey = nil
}

func (s *EnclaveServer) handleOwner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	owner, err := s.db.getOwner()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash := sha256.Sum256(owner)
	_, _ = w.Write(hash[:])
}

func (s *EnclaveServer) getOrCreateCertificate() ([]byte, crypto.PrivateKey, error) {
	cert, key, err := s.db.getCertificate()
	if err == nil {
		return cert, key, nil
	}
	if !errors.Is(err, db.ErrNotFound) {
		return nil, nil, err
	}
	cert, key, err = createCertificate()
	if err != nil {
		return nil, nil, err
	}
	s.appCertificate = cert
	s.appPrivKey = key
	return cert, key, nil
}

func createCertificate() ([]byte, crypto.PrivateKey, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: constants.EnclaveDNSName},
		NotBefore:    now.Add(-2 * time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		DNSNames:     []string{constants.EnclaveDNSName},
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}
