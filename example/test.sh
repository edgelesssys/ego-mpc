#!/bin/bash
set -e

onexit()
{
  if [[ $? -ne 0 ]]; then
    echo fail
  else
    echo pass
  fi
  set +e
  pkill ego-host
  pkill test-client
  rm -r "$tmp"
}

tmp=$(mktemp -d)
trap onexit EXIT
mkdir "$tmp/data"

# build server and client
ego-go build -buildvcs=false -o bin ./server
ego sign server/enclave.json
mv bin/server "$tmp"
CGO_CFLAGS=-I/opt/ego/include CGO_LDFLAGS=-L/opt/ego/lib go build -buildvcs=false -o "$tmp/test-client" ./client

cd "$tmp"

# generate certificates
openssl req -x509 -nodes -days 3650 -subj '/CN=owner' -keyout owner-key.pem -out owner-cert.pem
openssl req -x509 -nodes -days 3650 -subj '/CN=bank1' -keyout bank1-key.pem -out bank1-cert.pem
openssl req -x509 -nodes -days 3650 -subj '/CN=bank2' -keyout bank2-key.pem -out bank2-cert.pem

# run server and clients
UNIQUEID=$(ego uniqueid server)
OE_SIMULATION=1 ego run server &
./test-client -port 8000 -enclave-uid "$UNIQUEID" -cert owner-cert.pem -key owner-key.pem -owner-cert owner-cert.pem -insecure &
./test-client -port 8001 -enclave-uid "$UNIQUEID" -cert bank1-cert.pem -key bank1-key.pem -owner-cert owner-cert.pem -insecure &
./test-client -port 8002 -enclave-uid "$UNIQUEID" -cert bank2-cert.pem -key bank2-key.pem -owner-cert owner-cert.pem -insecure &

# wait for client and server to be ready
for _ in {0..9}; do
  curl -f http://localhost:8000/ready && break
  sleep 1
done

# use the API
curl -f http://localhost:8000/init
curl -f -d'{"money":2}' http://localhost:8001/api/account
curl -f -d'{"money":3}' http://localhost:8002/api/account
money=$(curl http://localhost:8001/api/money)
[[ "$money" = 5 ]]
