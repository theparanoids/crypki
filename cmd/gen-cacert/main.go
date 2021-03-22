// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/pkcs11"
)

var cfg string

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
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if cfg == "" {
		log.Fatal("no CA cert configuration file specified")
	}
	cfgData, err := ioutil.ReadFile(cfg)
	if err != nil {
		log.Fatal(err)
	}
	cc := &crypki.CAConfig{}
	if err := json.Unmarshal(cfgData, cc); err != nil {
		log.Fatal(err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}

	ips, err := getIPs()
	if err != nil {
		log.Fatal(err)
	}

	// create a new context, cancel it once the server exits
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// to make NewCertSign create the CA cert
	requireX509CACert := map[string]bool{
		cc.Identifier: true,
	}

	signer, err := pkcs11.NewCertSign(ctx, cc.PKCS11ModulePath,
		[]config.KeyConfig{{
			Identifier:             cc.Identifier,
			SlotNumber:             uint(cc.SlotNumber),
			UserPinPath:            cc.UserPinPath,
			KeyLabel:               cc.KeyLabel,
			KeyType:                crypki.PublicKeyAlgorithm(cc.KeyType),
			SignatureAlgo:          crypki.SignatureAlgorithm(cc.SignatureAlgo),
			SessionPoolSize:        2,
			X509CACertLocation:     "/tmp/509_ca.crt",
			CreateCACertIfNotExist: true,
			Country:                cc.Country,
			State:                  cc.State,
			Locality:               cc.Locality,
			Organization:           cc.Organization,
			OrganizationalUnit:     cc.OrganizationalUnit,
			CommonName:             cc.CommonName,
			ValidityPeriod:         cc.ValidityPeriod,
		}}, requireX509CACert, hostname, ips)
	if err != nil {
		log.Fatalf("unable to initialize cert signer: %v", err)
	}
	cert, err := signer.GetX509CACert(ctx, cc.Identifier)
	if err != nil {
		log.Fatalf("unable to get x509 CA cert: %v", err)
	}
	fmt.Println(string(cert))
}
