# EGo multi-party computing module

This module provides the base functionality for building confidential multi-party computing (MPC) apps in Intel SGX enclaves with [EGo](https://github.com/edgelesssys/ego).
MPC here refers to multiple users wanting to selectively share information through a shared host without revealing raw data.
More specifically, the module provides a server with a relational database handling trusted ownership, encryption, authentication, and secure connections with the client through attested TLS (aTLS).

## Architecture

An MPC server is implemented using the following packages:

* `server`: The server serves a user-defined HTTP REST API and handles attestation.
* `db`: The db package provides an encrypted SQLite database exposed via [GORM](https://gorm.io).
* `seal`: The seal package provides helper functions for sealing the database encryption key.

The client is implemented using the `client` package.
The idea is to run the client as a local proxy server that handles all the confidential-computing-related complexities, such as attestation and secure connections.
This allows to create user interfaces that can use standard HTTP connections to the local proxy.

## Example

To see how you can use the module, refer to the [example](./example/README.md).
