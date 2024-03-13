/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: MPL-2.0
*/

package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testServerCert = []byte("server")

func TestServerMux(t *testing.T) {
	const backendAddr = "backend"
	const report = "report"
	ownerCert := []byte("owner")
	ownerHash := sha256.Sum256(ownerCert)
	serverHash := sha256.Sum256(testServerCert)

	testCases := map[string]struct {
		req            *http.Request
		httpClient     stubHTTPClient
		verifyErr      error
		wantRespStatus int
		wantRespBody   string
	}{
		"api foward": {
			req: httptest.NewRequest(http.MethodPost, "/api/foo", strings.NewReader("req")),
			httpClient: stubHTTPClient{
				"https://backend/platform/attest": {status: http.StatusOK, body: report},
				"https://backend/platform/owner":  {status: http.StatusOK, body: string(ownerHash[:])},
				"https://backend/api/foo":         {status: 123, body: "resp"},
			},
			wantRespStatus: 123,
			wantRespBody:   "resp",
		},
		"api foward: query": {
			req: httptest.NewRequest(http.MethodPost, "/api/foo?a=b&c=d", strings.NewReader("req")),
			httpClient: stubHTTPClient{
				"https://backend/platform/attest": {status: http.StatusOK, body: report},
				"https://backend/platform/owner":  {status: http.StatusOK, body: string(ownerHash[:])},
				"https://backend/api/foo?a=b&c=d": {status: 123, body: "resp"},
			},
			wantRespStatus: 123,
			wantRespBody:   "resp",
		},
		"api forward: verify error": {
			req: httptest.NewRequest(http.MethodPost, "/api/foo", strings.NewReader("req")),
			httpClient: stubHTTPClient{
				"https://backend/platform/attest": {status: http.StatusOK, body: report},
				"https://backend/platform/owner":  {status: http.StatusOK, body: string(ownerHash[:])},
				"https://backend/api/foo":         {status: 123, body: "resp"},
			},
			verifyErr:      errors.New("failed"),
			wantRespStatus: http.StatusInternalServerError,
		},
		"api foward: unexpected owner": {
			req: httptest.NewRequest(http.MethodPost, "/api/foo", strings.NewReader("req")),
			httpClient: stubHTTPClient{
				"https://backend/platform/attest": {status: http.StatusOK, body: report},
				"https://backend/platform/owner":  {status: http.StatusOK, body: string(bytes.Repeat([]byte{2}, len(ownerHash)))},
				"https://backend/api/foo":         {status: 123, body: "resp"},
			},
			wantRespStatus: http.StatusInternalServerError,
		},
		"api foward: /attest fails": {
			req: httptest.NewRequest(http.MethodPost, "/api/foo", strings.NewReader("req")),
			httpClient: stubHTTPClient{
				"https://backend/platform/attest": {status: http.StatusServiceUnavailable, body: report},
				"https://backend/platform/owner":  {status: http.StatusOK, body: string(ownerHash[:])},
				"https://backend/api/foo":         {status: 123, body: "resp"},
			},
			wantRespStatus: http.StatusInternalServerError,
		},
		"api foward: /owner fails": {
			req: httptest.NewRequest(http.MethodPost, "/api/foo", strings.NewReader("req")),
			httpClient: stubHTTPClient{
				"https://backend/platform/attest": {status: http.StatusOK, body: report},
				"https://backend/platform/owner":  {status: http.StatusServiceUnavailable, body: string(ownerHash[:])},
				"https://backend/api/foo":         {status: 123, body: "resp"},
			},
			wantRespStatus: http.StatusInternalServerError,
		},
		"ready: backend OK": {
			req:            httptest.NewRequest(http.MethodGet, "/ready", http.NoBody),
			httpClient:     stubHTTPClient{"https://backend/platform/attest": {status: http.StatusOK}},
			wantRespStatus: http.StatusOK,
		},
		"ready: backend error": {
			req:            httptest.NewRequest(http.MethodGet, "/ready", http.NoBody),
			httpClient:     stubHTTPClient{"https://backend/platform/attest": {status: http.StatusServiceUnavailable}},
			wantRespStatus: http.StatusInternalServerError,
		},
		"ready: invalid method": {
			req:            httptest.NewRequest(http.MethodPost, "/ready", http.NoBody),
			wantRespStatus: http.StatusMethodNotAllowed,
		},
		"init: backend OK": {
			req:            httptest.NewRequest(http.MethodGet, "/init", http.NoBody),
			httpClient:     stubHTTPClient{"https://backend/platform/init": {status: http.StatusOK}},
			wantRespStatus: http.StatusOK,
		},
		"init: backend error": {
			req:            httptest.NewRequest(http.MethodGet, "/init", http.NoBody),
			httpClient:     stubHTTPClient{"https://backend/platform/init": {status: http.StatusServiceUnavailable}},
			wantRespStatus: http.StatusInternalServerError,
		},
		"init: invalid method": {
			req:            httptest.NewRequest(http.MethodPost, "/init", http.NoBody),
			wantRespStatus: http.StatusMethodNotAllowed,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			httpClientFactory := func(rootCA *x509.Certificate) HTTPClient {
				return &tc.httpClient
			}

			server, err := NewProxyServer(backendAddr, "1234", httpClientFactory, ownerCert, false)
			require.NoError(err)

			server.verifyReport = func(reportRaw []byte, uniqueID []byte, certHash []byte) error {
				assert.EqualValues(report, reportRaw)
				assert.Equal([]byte{0x12, 0x34}, uniqueID)
				assert.Equal(serverHash[:], certHash)
				return tc.verifyErr
			}

			resp := httptest.NewRecorder()
			server.Mux.ServeHTTP(resp, tc.req)

			assert.Equal(tc.wantRespStatus, resp.Code)
			if tc.wantRespBody != "" {
				assert.Equal(tc.wantRespBody, resp.Body.String())
			}
		})
	}
}

type stubHTTPClient map[string]struct {
	status int
	body   string
}

func (h *stubHTTPClient) Do(req *http.Request) (*http.Response, error) {
	resp, ok := (*h)[req.URL.String()]
	if !ok {
		panic(req.URL)
	}
	return &http.Response{
		StatusCode: resp.status,
		Body:       io.NopCloser(strings.NewReader(resp.body)),
		TLS:        &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: testServerCert}}},
	}, nil
}
