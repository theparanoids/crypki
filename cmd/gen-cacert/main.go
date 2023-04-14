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
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/pkcs11"
	"github.com/theparanoids/crypki/server/scheduler"
)

const (
	defaultCAOutPath = "/tmp/509_ca.crt"
)

var cfg string
var caOutPath string
var skipHostname bool
var skipIPs bool
var uri string

func getIPs() (ips []net.IP, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("unable to fetch interfaces: " + err.Error())
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, errors.New("unable to extract addresses from interface: " + err.Error())
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func main() {
	flag.StringVar(&cfg, "config", "", "CA cert configuration file")
	flag.StringVar(&caOutPath, "out", defaultCAOutPath, "the output path of the generated CA cert")
	flag.BoolVar(&skipHostname, "skip-hostname", false, "skip including dnsName attribute in CA cert")
	flag.BoolVar(&skipIPs, "skip-ips", false, "skip including IP attribute in CA cert")
	flag.StringVar(&uri, "uri", "", "URI value to include in CA cert SAN")

	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lmicroseconds | log.Lshortfile)

	if cfg == "" {
		log.Fatal("no CA cert configuration file specified")
	}
	if caOutPath == "" {
		caOutPath = defaultCAOutPath
	}

	cfgData, err := os.ReadFile(cfg)
	if err != nil {
		log.Fatal(err)
	}
	cc := &crypki.CAConfig{}
	if err := json.Unmarshal(cfgData, cc); err != nil {
		log.Fatal(err)
	}

	hostname := ""
	if !skipHostname {
		hostname, err = os.Hostname()
		if err != nil {
			log.Fatal(err)
		}
	}

	var ips []net.IP
	if !skipIPs {
		ips, err = getIPs()
		if err != nil {
			log.Fatal(err)
		}
	}

	var uris []*url.URL
	if uri != "" {
		parsedUri, err := url.Parse(uri)
		if err != nil {
			log.Fatal(err)
		}
		uris = []*url.URL{parsedUri}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// to make NewCertSign create the CA cert
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
		X509CACertLocation:     caOutPath,
		CreateCACertIfNotExist: true,
		Country:                cc.Country,
		State:                  cc.State,
		Locality:               cc.Locality,
		Organization:           cc.Organization,
		OrganizationalUnit:     cc.OrganizationalUnit,
		CommonName:             cc.CommonName,
		ValidityPeriod:         cc.ValidityPeriod,
	}}, requireX509CACert, hostname, ips, uris, config.DefaultPKCS11Timeout)
	if err != nil {
		log.Fatalf("unable to initialize cert signer: %v", err)
	}
	cert, err := signer.GetX509CACert(ctx, requestChan, cc.Identifier)
	if err != nil {
		log.Fatalf("unable to get x509 CA cert: %v", err)
	}
	fmt.Println(string(cert))
}
