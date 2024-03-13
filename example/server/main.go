package main

import (
	"crypto/x509"
	"log"

	"github.com/edgelesssys/ego-mpc/example/server/api"
	"github.com/edgelesssys/ego-mpc/example/server/db"
	"github.com/edgelesssys/ego-mpc/server"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}

	conn, err := db.New("encrypted.db")
	if err != nil {
		log.Fatal(err)
	}

	onInit := func(owner *x509.Certificate) error {
		// define the business specific initialization logic here
		return nil
	}

	api := api.NewAPI(logger, conn)
	server := server.New(conn.EncryptedDB, api.GetHTTPHandler().ServeHTTP, onInit)
	server.Run("8080")
}
