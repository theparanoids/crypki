[![Build Status][build-badge]][build-url] [![GoDoc][godoc-badge]][godoc] [![Go Report Card][goreport-card-badge]][goreport-card] [![Go Coverage][codecov-card-badge]][codecov-card] [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5720/badge)](https://bestpractices.coreinfrastructure.org/projects/5720)


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

- Go >= 1.18

Run:

```sh
go install github.com/theparanoids/crypki/cmd/crypki@latest
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

Take a look at the [sample configuration file](https://github.com/theparanoids/crypki/blob/main/config/testdata/testconf-good.json) to see how to configure crypki

## API

APIs for crypki are defined under [crypki/proto](https://github.com/theparanoids/crypki/tree/main/proto). If you are familiar with or are using grpc, you can directly invoke the rpc methods defined in the proto file.

Examples:
 
Get all available SSH signing keys
  ```sh
  curl -X GET https://localhost:4443/v3/sig/ssh-user-cert/keys --cert tls-crt/client.crt --key tls-crt/client.key --cacert tls-crt/ca.crt
   ```

Get SSH user public signing key (CA public key for ssh-user-cert) 
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

## CA credentials 

### Extract SSH CA public key for a key identifier 

  > Note: [init_hsm.sh](./docker-softhsm/init_hsm.sh) extracts the public keys of each key slot from the SoftHSM, and stores inside the container.  
  
  Following script exports the public key (in PEM format) of slot `user_ssh_pub` from the container, and converts it into SSH format.    

  ```sh
   docker cp crypki:/opt/crypki/slot_pubkeys/user_ssh_pub.pem ~/tmp/user_ssh_pub.pem 
   ssh-keygen -f ~/tmp/user_ssh_pub.pem -i -mPKCS8
  ```

### Generate a self-signed X509 CA cert for a key identifier

  Generate a self-signed X509 CA cert for key identifier `x509-key` by `gen-cacert` binary.  

  ```sh
  # Get into the shell of crypki container. 
  docker exec -ti crypki /bin/bash
  # Refer to `/opt/crypki/crypki-softhsm.json` and `init_hsm.sh` to find out the attributes $SLOT_NUMBER, $KEY_LABEL, and $USER_PIN.
  # In the example, our keyLabel is host_x509, keyType is 3 and signatureAlgorithm is 11 for `x509-key`.  
  
  echo $USER_PIN > /tmp/user_pin
  cat > /tmp/ca_crt_config.json <<EOF
{
  "Identifier": "x509-key",
  "CommonName": "www.example.com",
  "KeyLabel": "host_x509",
  "KeyType": 3,
  "SignatureAlgo": 11,
  "PKCS11ModulePath": "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
  "SlotNumber": $SLOT_NUMBER,
  "UserPinPath": "/tmp/user_pin"
}
EOF
  /usr/bin/gen-cacert -config=/tmp/ca_crt_config.json -out=/tmp/x509-ca.cert
  # You will see a newly signed x509 CA certificate printed and written to the `-out` path.  
  ```

## Contribute

- Please refer to [Contributing.md](Contributing.md) for information about how to get involved. We welcome issues, questions and pull requests.

- You can also contact us for any user and development discussions through our group [crypki-dev](https://groups.google.com/d/forum/crypki-dev)

- [Code of Conduct](Code-of-Conduct.md)

## License

This project is licensed under the terms of the [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0) open source license. Please refer to [LICENSE](LICENSE) for the full terms.

[build-badge]:     https://github.com/theparanoids/crypki/workflows/Linux/badge.svg
[build-url]:       https://github.com/theparanoids/crypki/actions?query=branch%3Amain+workflow%3ALinux
[golang]:          http://golang.org/
[golang-install]:  http://golang.org/doc/install.html#releases
[godoc-badge]:     https://pkg.go.dev/badge/github.com/theparanoids/crypki.svg
[godoc]:           https://pkg.go.dev/github.com/theparanoids/crypki
[goreport-card-badge]: https://goreportcard.com/badge/theparanoids/crypki
[goreport-card]: https://goreportcard.com/report/theparanoids/crypki
[codecov-card-badge]: https://codecov.io/gh/theparanoids/crypki/branch/main/graph/badge.svg
[codecov-card]: https://codecov.io/gh/theparanoids/crypki
