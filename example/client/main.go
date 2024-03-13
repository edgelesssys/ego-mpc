package main

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/edgelesssys/ego-mpc/client"
)

func main() {
	// parse command line arguments
	port := flag.String("port", "", "listen port (required)")
	enclaveAddr := flag.String("enclave-addr", "localhost:8080", "address of the server enclave")
	uniqueID := flag.String("enclave-uid", "", "UniqueID of the server enclave (required)")
	certFilename := flag.String("cert", "", "client certificate PEM file (required)")
	keyFilename := flag.String("key", "", "client private key PEM file (required)")
	ownerCertFilename := flag.String("owner-cert", "", "owner certificate PEM file (required)")
	insecure := flag.Bool("insecure", false, "ignore attestation errors")
	flag.Parse()
	if *port == "" || *uniqueID == "" || *certFilename == "" || *keyFilename == "" || *ownerCertFilename == "" {
		flag.Usage()
		os.Exit(1)
	}

	// load certificates
	cert, err := tls.LoadX509KeyPair(*certFilename, *keyFilename)
	if err != nil {
		log.Fatalln("Failed to load key pair:", err)
	}
	ownerCert, err := loadCertFromPEM(*ownerCertFilename)
	if err != nil {
		log.Fatalln("Failed to load owner certificate:", err)
	}

	// The proxy server connects to the enclave for the actual client to hide the complexity of authentication and attestation.
	log.Println("Enclave address:", *enclaveAddr)
	server, err := client.NewProxyServer(*enclaveAddr, *uniqueID, client.DefaultHTTPClientFactory(cert), ownerCert, *insecure)
	if err != nil {
		log.Fatalln("Failed to create proxy server:", err)
	}

	addr := net.JoinHostPort("0.0.0.0", *port)
	log.Println("Listening on", addr, "...")
	err = server.Run(addr)
	if err != nil {
		log.Fatalln("Failed to listen:", err)
	}
}

func loadCertFromPEM(certFilename string) ([]byte, error) {
	cert, err := os.ReadFile(certFilename)
	if err != nil {
		return nil, fmt.Errorf("reading certificate: %w", err)
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("decoding certificate failed")
	}
	return block.Bytes, nil
}
