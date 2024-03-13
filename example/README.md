# Example application - User data exchange

This is an example to demonstrate a use case for the EGo MPC module.
In this example, banks can selectively share data, such as the global amount of money, while keeping sensitive user information, such as individual names and amounts of money, private. The business API is made consumable through a REST HTTP API to hide the complexities around authentication and attestation. As a result, another component or application, such as a web app, can access the API while delegating the hidden complexity to the EGo MPC client server.

## Structure

The example consists of the following components:

- `server`: The MPC server running in an enclave. It includes the business logic and the MPC module.
  - `api`: The business API handles the client requests and uses the database.
  - `db`: The database defines the model and provides methods to access the database.
  - `enclave.json`: The enclave configuration file. In addition to the required values, it mounts the `data` folder of the current directory to the enclave to store the encrypted database.
- `client`: The MPC client server.

## Build

You can build the server and client as follows:

```bash
cd bin
ego-go build ../server
ego sign ../server/enclave.json
CGO_CFLAGS=-I/opt/ego/include CGO_LDFLAGS=-L/opt/ego/lib go build ../client
```

## Generate certificates

To authenticate the client against the server, the client provides a certificate key pair. Generate certificate key pairs for the owner and for the banks:

``` bash
openssl req -x509 -nodes -days 3650 -subj '/CN=owner' -keyout owner-key.pem -out owner-cert.pem
openssl req -x509 -nodes -days 3650 -subj '/CN=bank1' -keyout bank1-key.pem -out bank1-cert.pem
openssl req -x509 -nodes -days 3650 -subj '/CN=bank2' -keyout bank2-key.pem -out bank2-cert.pem
```

## Run the server

You can run the server with `ego run` as usual:

```bash
ego run server
```

## Run the clients

First get the UniqueID of the server:

```bash
ego uniqueid server
```

Then run each client in a separate terminal:

```bash
./client -port 8000 -enclave-uid <server's UniqueID> -cert owner-cert.pem -key owner-key.pem -owner-cert owner-cert.pem
```

```bash
./client -port 8001 -enclave-uid <server's UniqueID> -cert bank1-cert.pem -key bank1-key.pem -owner-cert owner-cert.pem
```

```bash
./client -port 8002 -enclave-uid <server's UniqueID> -cert bank2-cert.pem -key bank2-key.pem -owner-cert owner-cert.pem
```

In addition to their own key pair, the clients provide an additional flag `-owner-cert` to verify that the provided identity owns the enclave. An owner might have specific privileges, so this ensures that the trusted admin is indeed the enclave owner.

Each client runs a proxy server on the defined port to handle the secure connection and authentication with the enclave. The client runs a server to ease the consumption of the API outside of Go binaries, e.g., the browser.

### Initialization

The MPC enclave server includes an `/init` endpoint, which needs to be called once to make the business API available. You can define additional custom behavior of `/init` as part of the business logic. This is a no-op in the example. In a production use case, it might be used to define ownership, for example, in the form of an admin with special permission privileges.

To initialize the enclave and define the admin client as the owner, run:

```bash
curl http://localhost:8000/init
```

Note that this can be only done once and that any calls to `/api/*` only work after initialization.

### Example API usage

Through the authenticated client server, you can access the API through HTTP.

To create some accounts by bank 1:

```bash
curl -d '{"Name":"Joe Doe", "Money":1000}' http://localhost:8001/api/account
curl -d '{"Name":"Jane Smith", "Money":2000}' http://localhost:8001/api/account
```

To create an account by bank 2:

```bash
curl -d '{"Name":"John Jones", "Money":3000}' http://localhost:8002/api/account
```

To get all accounts of bank 1:

```bash
curl http://localhost:8001/api/account
```

You can verify that running this on the owner (`:8000`) or bank 2 (`:8002`) client won't show the accounts of bank 1.

To get the total amount of money from all accounts:

```bash
curl http://localhost:8001/api/money
```

## Development

When embedding the MPC module for your use case, there are a few things you might want to modify from the example:

- Add permission checks: in this example, everyone can act as a bank. You may only allow client certificates that are signed by a specific CA or that have been registered by the owner.
- Define the `onInit` behavior on the enclave server (`example/server/main.go`). It lets you define application specific ownership logic. For example in the form of special admin permission privileges.
- Define the business API (`example/server/api`). The endpoints should be prefixed with `/api` to indicate that this is business logic that should be forwarded by the client server to the enclave.
- Define the business specific database model (`example/server/db`). The MPC module includes an encrypted SQL database where you can define data structures through GORM, a popular ORM library for Go.
