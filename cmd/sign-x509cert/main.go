// Copyright 2021 Yahoo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/pkcs11"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/server/scheduler"
)

var cfg string
var validityDays uint64
var csrPath string
var caPath string
var certOutPath string

func parseFlags() {
	flag.StringVar(&cfg, "config", "", "CA key configuration file")
	flag.Uint64Var(&validityDays, "days", 730, "validity period in days")
	flag.StringVar(&caPath, "cacert", "", "path to CA cert")
	flag.StringVar(&csrPath, "in", "", "CSR path")
	flag.StringVar(&certOutPath, "out", "", "the output path of signed cert (The same dir path of the given csr will be applied if this var is not specified.)")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if cfg == "" {
		log.Fatal("no CA key configuration file specified")
	}

	if caPath == "" {
		log.Fatal("no ca cert path specified")
	}

	if csrPath == "" {
		log.Fatal("no CSR path specified")
	}

	if certOutPath == "" {
		certOutPath = fmt.Sprintf("%s.%s", strings.TrimSuffix(csrPath, filepath.Ext(csrPath)), "crt")
	}
}

func constructUnsignedX509Cert() *x509.Certificate {
	csrData, err := os.ReadFile(csrPath)
	if err != nil {
		log.Fatalf("failed to read csrPath file: %v", err)
	}

	csrBlock, _ := pem.Decode(csrData)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		log.Fatalf("failed to parse cert request: %v", err)
	}

	return &x509.Certificate{
		Subject:               csr.Subject,
		SerialNumber:          newSerial(),
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		NotBefore:             time.Now().Add(-time.Hour), // backdate to address possible clock drift
		NotAfter:              time.Now().Add(time.Hour * 24 * time.Duration(validityDays)),
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func newSerial() *big.Int {
	const (
		minBits   = 64  // https://cabforum.org/2016/03/31/ballot-164/
		maxBits   = 160 // https://tools.ietf.org/html/rfc5280#section-4.1.2.2
		tolerance = 2
	)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), maxBits-minBits-tolerance)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	return serialNumber.Lsh(serialNumber, minBits)
}

func main() {
	parseFlags()

	cfgData, err := os.ReadFile(cfg)
	if err != nil {
		log.Fatal(err)
	}
	cc := &crypki.CAConfig{}
	if err := json.Unmarshal(cfgData, cc); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// x509 requires CA certs.
	requireX509CACert := map[string]bool{
		cc.Identifier: true,
	}

	requestChan := make(chan scheduler.Request)
	p := &scheduler.Pool{Name: cc.Identifier, PoolSize: 2, FeatureEnabled: true, PKCS11Timeout: config.DefaultPKCS11Timeout * time.Second}
	go scheduler.CollectRequest(ctx, requestChan, p)

	signer, err := pkcs11.NewCertSign(ctx, cc.PKCS11ModulePath, []config.KeyConfig{{
		Identifier:             cc.Identifier,
		SlotNumber:             uint(cc.SlotNumber),
		UserPinPath:            cc.UserPinPath,
		KeyLabel:               cc.KeyLabel,
		KeyType:                x509.PublicKeyAlgorithm(cc.KeyType),
		SignatureAlgo:          x509.SignatureAlgorithm(cc.SignatureAlgo),
		SessionPoolSize:        2,
		X509CACertLocation:     caPath,
		CreateCACertIfNotExist: false,
	}}, requireX509CACert, "", nil, config.DefaultPKCS11Timeout) // Hostname and ips should not be needed as CreateCACertIfNotExist is set to be false.

	if err != nil {
		log.Fatalf("unable to initialize cert signer: %v", err)
	}

	unsignedCert := constructUnsignedX509Cert()

	data, err := signer.SignX509Cert(ctx, requestChan, unsignedCert, cc.Identifier, proto.Priority_Unspecified_priority)
	if err != nil {
		log.Fatalf("falied to sign x509 cert: %v", err)
	}

	if err := os.WriteFile(certOutPath, data, 0444); err != nil {
		log.Printf("the newly signed cert has been generated, but unable to write to file %s: %v", certOutPath, err)
	} else {
		log.Printf("the newly signed x509 cert has been written to %s", certOutPath)
	}
}
