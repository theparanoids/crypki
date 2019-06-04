 # Testdata
 
 Steps to generate testdata under various folders:

   1. Generate EC and RSA private keys

   ```
      openssl ecparam -name prime256v1 -genkey -out ec.key.pem
      openssl genrsa -out rsa.key.pem 4096
   ```

   2. Generate signing requests from the RSA private key and this conf

   ```
      openssl req -new -key rsa.key.pem -config openssl.cnf -out csr.pem
   ```

   3. Self-signing using the CSRs and the private keys

   ```
      openssl x509 -text -req -in csr.pem -signkey ec.key.pem -out ec.cert.pem
      openssl x509 -text -req -in csr.pem -signkey rsa.key.pem -out rsa.cert.pem
   ```
