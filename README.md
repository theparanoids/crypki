[![Build Status][travis-ci-badge]][travis-ci] [![GoDoc][godoc-badge]][godoc] [![Go Report Card][goreport-card-badge]][goreport-card] [![Go Coverage][codecov-card-badge]][codecov-card]


# crypki
> _A simple service for interacting with an HSM or other PKCS#11 device._

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Configuration](#configuration)
- [API](#api)
- [Contribute](#contribute)
- [License](#license)

## Background

A simple service for interacting with an HSM or other PKCS #11 device. It supports minting and signing of both SSH and x509 certificates. Crypki is the certificate signing backend for the [Athenz](https://github.com/yahoo/athenz) RBAC system. 

## Install

You should be able to run crypki server on any linux platform as long as you have crypki binary and .so file. We have tested it on RHEL 7, Debian 9 & Ubuntu 18.04. 

### Building crypki from source

Prerequisites:

- Go >= 1.13

Run:

```sh
go get github.com/yahoo/crypki
```

## Usage 

To start crypki server clone the repo and run the following commands.

- Build docker image
  ```sh
  $ docker build -f docker-softhsm/Dockerfile -t crypki-local .
  ```

If you want to speed up docker image build process, before running the command above, you can cache the dependencies locally using the following command.
```sh
$ go mod vendor
```

- Generate certs and keys required for mutual TLS between the front end-client and the crypki backend server
  ```sh
  cd docker-softhsm
  ./gen-crt.sh
  ```
  
- Start the docker container
  ```sh
  docker run -d -p :4443:4443 -v $PWD/log:/var/log/crypki -v $PWD/tls-crt:/opt/crypki/tls-crt:ro -v $PWD/shm:/dev/shm --rm --name crypki -h "localhost" crypki-local
  ```  
  
- Verify whether the server is up and running
  ```sh
  curl -X GET https://localhost:4443/ruok --cert tls-crt/client.crt --key tls-crt/client.key --cacert tls-crt/ca.crt 
  ```
 
**Disclaimer:** _the above installation guidelines are to help you to get started with crypki; they should be used only for testing/development purposes. Please do not use this setup for production, because it is not secure._


## Configuration
Take a look at the [sample configuration file](https://github.com/yahoo/crypki/blob/master/config/testdata/testconf-good.json) to see how to configure crypki

## API

APIs for crypki are defined under [crypki/proto](https://github.com/yahoo/crypki/tree/master/proto). If you are familiar with or are using grpc, you can directly invoke the rpc methods defined in the proto file.  

Examples:
 
Get all available SSH signing keys
  ```sh
  curl -X GET https://localhost:4443/v3/sig/ssh-user-cert/keys --cert tls-crt/client.crt --key tls-crt/client.key --cacert tls-crt/ca.crt
   ```

Get SSH user public signing key
  ```sh
  curl -X GET https://localhost:4443/v3/sig/ssh-user-cert/keys/ssh-user-key --cert tls-crt/client.crt --key tls-crt/client.key --cacert tls-crt/ca.crt
   ```

Sign SSH user certificate
  ```sh
  curl -X POST -H "Content-Type: application/json" https://localhost:4443/v3/sig/ssh-user-cert/keys/ssh-user-key --data @ssh_csr.json --cert tls-crt/client.crt --key tls-crt/client.key --cacert tls-crt/ca.crt 
  ```

Get all available x509 signing keys
  ```sh
  curl -X GET https://localhost:4443/v3/sig/x509-cert/keys --cert tls-crt/client.crt --key tls-crt/client.key --cacert tls-crt/ca.crt
   ```

Get x509 public CA certificate
  ```sh
  curl -X GET https://localhost:4443/v3/sig/x509-cert/keys/x509-key --cert tls-crt/client.crt --key tls-crt/client.key --cacert tls-crt/ca.crt
   ```

Sign x509 certificate
  ```sh
  curl -X POST -H "Content-Type: application/json" https://localhost:4443/v3/sig/x509-cert/keys/x509-key --data @x509_csr.json --cert tls-crt/client.crt --key tls-crt/client.key --cacert tls-crt/ca.crt 
  ```

Get blob signing public key
  ```sh
  curl -X GET https://localhost:4443/v3/sig/blob/keys/sign-blob-key --cert tls-crt/client.crt --key tls-crt/client.key --cacert tls-crt/ca.crt
  ```

Sign blob (input is base64 encoded value of raw hash of a blob. [example code](https://play.golang.org/p/AFlho2HtZoD))
  ```sh
  curl -X POST -H "Content-Type: application/json" https://localhost:4443/v3/sig/blob/keys/sign-blob-key --data @sign_blob.json --cert tls-crt/client.crt --key tls-crt/client.key --cacert tls-crt/ca.crt
  ```

## Contribute

- Please refer to [Contributing.md](Contributing.md) for information about how to get involved. We welcome issues, questions and pull requests.

- You can also contact us for any user and development discussions through our group [crypki-dev](https://groups.google.com/d/forum/crypki-dev)

- [Code of Conduct](Code-of-Conduct.md)

## License

This project is licensed under the terms of the [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0) open source license. Please refer to [LICENSE](LICENSE) for the full terms.

[golang]:          http://golang.org/
[golang-install]:  http://golang.org/doc/install.html#releases
[travis-ci-badge]: https://travis-ci.com/yahoo/crypki.svg?branch=master
[travis-ci]:       https://travis-ci.com/yahoo/crypki
[godoc-badge]:     https://godoc.org/github.com/yahoo/crypki?status.svg
[godoc]:           https://godoc.org/github.com/yahoo/crypki
[goreport-card-badge]: https://goreportcard.com/badge/yahoo/crypki
[goreport-card]: https://goreportcard.com/report/yahoo/crypki
[codecov-card-badge]: https://codecov.io/gh/yahoo/crypki/branch/master/graph/badge.svg
[codecov-card]: https://codecov.io/gh/yahoo/crypki
