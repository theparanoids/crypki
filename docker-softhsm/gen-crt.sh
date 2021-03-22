#! /bin/bash
# This file generates the rsa certificates and keys for demonstration

set -euo pipefail

mkdir -p tls-crt && cd tls-crt

# generate root CA certificate
openssl \
  req \
  -newkey rsa:4096 -nodes \
  -keyout ca.key \
  -x509 -days 36500 -out ca.crt \
  -subj "/C=US/ST=NRW/L=Earth/O=CompanyName/OU=IT/CN=www.example.com/emailAddress=email@example.com"

# generate server private key
openssl genrsa -out server.key 4096

# generate server certificate signing request
openssl \
  req \
  -new -sha256 \
  -key server.key \
	-subj "/C=US/CN=localhost" \
  -out server.csr

# sign server.csr by root CA 
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 36500 -sha256


# for mutual TLS

# generate client private key
openssl genrsa -out client.key 4096

# generate tls_client certificate signing request
openssl \
  req \
  -new -sha256 \
  -key client.key \
	-subj "/C=US/CN=localhost" \
  -out client.csr

# sign tls_client.csr by root CA 
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 36500 -sha256

rm *.csr ca.key *.srl