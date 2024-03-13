/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: MPL-2.0
*/

package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/edgelesssys/ego-mpc/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	api := http.NewServeMux()
	api.HandleFunc("/api/foo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("resp"))
	})

	db, err := db.New(":memory:", bytes.Repeat([]byte{0}, db.KeySize))
	require.NoError(err)

	// create server and change state to uninitialized
	server := New(db, api.ServeHTTP, nil)
	server.appCertificate = []byte("cert")
	server.appPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(err)

	// uninitialized server should return Not Found
	resp := serve(server, httptest.NewRequest(http.MethodGet, "/api/foo", http.NoBody))
	require.Equal(http.StatusNotFound, resp.Code)

	// initialize server
	resp = serve(server, httptest.NewRequest(http.MethodGet, "/platform/init", http.NoBody))
	require.Equal(http.StatusOK, resp.Code)

	// initialized server should return OK
	resp = serve(server, httptest.NewRequest(http.MethodGet, "/api/foo", http.NoBody))
	require.Equal(http.StatusOK, resp.Code)
	assert.Equal("resp", resp.Body.String())
}

func serve(server *EnclaveServer, req *http.Request) *httptest.ResponseRecorder {
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{createTestCertificate()}}
	resp := httptest.NewRecorder()
	server.mux.ServeHTTP(resp, req)
	return resp
}

func createTestCertificate() *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: &big.Int{},
		NotAfter:     time.Now().Add(time.Hour),
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		panic(err)
	}
	return cert
}
