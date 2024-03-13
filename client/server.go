/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: MPL-2.0
*/

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/edgelesssys/ego-mpc/internal/constants"
)

// ServerName is the SAN of the server's X.509 certificate.
const ServerName = constants.EnclaveDNSName

// DefaultHTTPClientFactory returns a secure HTTPClientFactory suitable for the most common uses.
func DefaultHTTPClientFactory(clientCertificate tls.Certificate) HTTPClientFactory {
	// The local proxy server requires an HTTPClient factory that creates two kinds of clients:
	// - a client for the init call and for attestation that must always accept the self-signed certificate of the enclave (rootCA == nil)
	// - a client for all other calls that must verify the certificate of the enclave obtained during attestation (rootCA != nil)
	return func(rootCA *x509.Certificate) HTTPClient {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{clientCertificate},
		}
		if rootCA == nil {
			tlsConfig.InsecureSkipVerify = true
		} else {
			tlsConfig.RootCAs = x509.NewCertPool()
			tlsConfig.RootCAs.AddCert(rootCA)
			tlsConfig.ServerName = ServerName
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	}
}

type Server struct {
	Mux *http.ServeMux

	backendServerAddr string
	uniqueID          []byte
	httpClientFactory HTTPClientFactory
	ownerCert         []byte
	insecure          bool
	verifyReport      func(reportRaw []byte, uniqueID []byte, certHash []byte) error

	mut         sync.Mutex
	enclaveCert *x509.Certificate
}

// NewProxyServer creates a new server that forwards requests to the backend server, handling attestation and authentication.
func NewProxyServer(backendServerAddr string, uniqueID string, httpClientFactory HTTPClientFactory, ownerCert []byte, insecure bool) (*Server, error) {
	uniqueIDBytes, err := hex.DecodeString(uniqueID)
	if err != nil {
		return nil, fmt.Errorf("decoding uniqueID: %w", err)
	}
	s := &Server{
		Mux:               http.NewServeMux(),
		backendServerAddr: backendServerAddr,
		uniqueID:          uniqueIDBytes,
		httpClientFactory: httpClientFactory,
		ownerCert:         ownerCert,
		insecure:          insecure,
		verifyReport:      verifyReport,
	}
	s.Mux.HandleFunc("/init", s.handleInit)
	s.Mux.HandleFunc("/api/", s.handleAPI)
	s.Mux.HandleFunc("/ready", s.handleReady)
	return s, nil
}

// Run runs the server on the given address.
func (s *Server) Run(address string) error {
	server := http.Server{
		Addr:    address,
		Handler: s.Mux,
	}
	return server.ListenAndServe()
}

func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	resp, err := s.httpGet(r.Context(), "platform/init", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, resp.Status, http.StatusInternalServerError)
		return
	}
}

// handleAPI forwards requests to the backend server.
func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	if corsHandling(&w, r) {
		return
	}

	fullURL, err := url.JoinPath("https:", s.backendServerAddr, r.URL.Path)
	if err != nil {
		httpInternalError(w, r, "creating URL", err)
		return
	}
	if r.URL.RawQuery != "" {
		fullURL += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, fullURL, r.Body)
	if err != nil {
		httpInternalError(w, r, "creating request", err)
		return

	}
	// copy content for multi part forms
	req.Header = r.Header.Clone()
	req.MultipartForm = r.MultipartForm

	enclaveCert, err := s.verifyAttestation(r.Context())
	if err != nil {
		if !s.insecure {
			httpInternalError(w, r, "verifying attestation", err)
			return
		}
		log.Printf("WARNING: verifying attestation: %v", err)
	}

	resp, err := s.httpClientFactory(enclaveCert).Do(req)
	if err != nil {
		httpInternalError(w, r, "performing request", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		httpInternalError(w, r, "reading response", err)
		return
	}

	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// handleReady checks if the client is ready and is able to connect to the backend server.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	resp, err := s.httpGet(r.Context(), "platform/attest", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, resp.Status, http.StatusInternalServerError)
		return
	}
}

func (s *Server) verifyAttestation(ctx context.Context) (*x509.Certificate, error) {
	s.mut.Lock()
	defer s.mut.Unlock()

	if s.enclaveCert != nil {
		// already verified
		return s.enclaveCert, nil
	}

	// get remote report
	resp, err := s.httpGet(ctx, "platform/attest", nil)
	if err != nil {
		return nil, fmt.Errorf("getting attestation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getting attestation: %v", resp.Status)
	}
	report, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading attestation: %w", err)
	}

	cert := resp.TLS.PeerCertificates[0]

	if s.insecure {
		// assume cert is trusted even if attestation may fail
		s.enclaveCert = cert
	}

	// verify report and server certificate
	certHash := sha256.Sum256(cert.Raw)
	if err := s.verifyReport(report, s.uniqueID, certHash[:]); err != nil {
		return nil, fmt.Errorf("verifying report: %w", err)
	}

	// verify owner
	resp, err = s.httpGet(ctx, "platform/owner", cert)
	if err != nil {
		return nil, fmt.Errorf("getting owner: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getting owner: %v", resp.Status)
	}
	actualOwnerHash, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading owner: %w", err)
	}
	expectedOwnerHash := sha256.Sum256(s.ownerCert)
	if !bytes.Equal(actualOwnerHash, expectedOwnerHash[:]) {
		return nil, fmt.Errorf("invalid owner hash: expected %x, got %x", expectedOwnerHash, actualOwnerHash)
	}

	s.enclaveCert = cert
	return cert, nil
}

func (s *Server) httpGet(ctx context.Context, endpoint string, rootCA *x509.Certificate) (*http.Response, error) {
	fullURL, err := url.JoinPath("https:", s.backendServerAddr, endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	return s.httpClientFactory(rootCA).Do(req)
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type HTTPClientFactory func(rootCA *x509.Certificate) HTTPClient

func corsHandling(w *http.ResponseWriter, r *http.Request) bool {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type")
	(*w).Header().Set("Content-Type", "application/json")

	return r.Method == http.MethodOptions
}

func httpInternalError(w http.ResponseWriter, r *http.Request, msg string, err error) {
	msg = fmt.Sprintf("%v: %v", msg, err)
	log.Printf("ERROR: %v %v: %v", r.Method, r.URL, msg)
	http.Error(w, msg, http.StatusInternalServerError)
}
