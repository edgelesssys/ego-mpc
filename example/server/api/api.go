package api

/*
The api package defines an HTTP handler containing the business logic of the server.
*/

import (
	"encoding/json"
	"net/http"

	"github.com/edgelesssys/ego-mpc/example/server/db"
	"go.uber.org/zap"
)

type Handler struct {
	logger *zap.Logger
	db     *db.DB
}

func NewAPI(logger *zap.Logger, db *db.DB) *Handler {
	return &Handler{logger: logger, db: db}
}

func (s *Handler) GetHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/account", s.handleAccount)
	mux.HandleFunc("/api/money", s.getMoney)
	return mux
}

func (s *Handler) handleAccount(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getAccounts(w, r)
	case http.MethodPost:
		s.createAccount(w, r)
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (s *Handler) getAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.db.GetAccounts(s.getClientID(r))
	if err != nil {
		s.logger.Error("getting accounts", zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(accounts); err != nil {
		s.logger.Error("encoding accounts", zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Handler) createAccount(w http.ResponseWriter, r *http.Request) {
	var account db.Account
	if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
		s.logger.Error("decoding account", zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.db.CreateAccount(account, s.getClientID(r)); err != nil {
		s.logger.Error("creating account", zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Handler) getMoney(w http.ResponseWriter, r *http.Request) {
	money, err := s.db.GetGlobalMoney()
	if err != nil {
		s.logger.Error("getting money", zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(money); err != nil {
		s.logger.Error("encoding money", zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// getClientID returns a client ID based on the client's certificate.
func (s *Handler) getClientID(r *http.Request) string {
	cert := r.TLS.PeerCertificates[0]
	return string(cert.Raw)
}
