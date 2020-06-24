// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/theparanoids/crypki"
)

const (
	defaultModulePath        = "/opt/utimaco/lib/libcs_pkcs11_R2.so"
	defaultTLSServerCertPath = "/opt/crypki/server.crt"
	defaultTLSCACertPath     = "/opt/crypki/ca.crt"
	defaultTLSServerKeyPath  = "/opt/crypki/server.key"
	defaultTLSHost           = ""
	defaultTLSPort           = "4443"
	defaultPoolSize          = 2
	defaultKeyType           = crypki.RSA

	// X509CertEndpoint specifies the endpoint for signing X509 certificate.
	X509CertEndpoint = "/sig/x509-cert"
	// SSHUserCertEndpoint specifies the endpoint for signing SSH user certificate.
	SSHUserCertEndpoint = "/sig/ssh-user-cert"
	// SSHHostCertEndpoint specifies the endpoint for signing SSH host certificate.
	SSHHostCertEndpoint = "/sig/ssh-host-cert"
	// BlobEndpoint specifies the endpoint for raw signing.
	BlobEndpoint = "/sig/blob"
)

var endpoints = map[string]bool{
	X509CertEndpoint:    true,
	SSHUserCertEndpoint: true,
	SSHHostCertEndpoint: true,
	BlobEndpoint:        true,
}

// KeyUsage configures which key(s) can be used for the API call.
type KeyUsage struct {
	// Endpoint represents the API call that is made.
	// E.g. "/sig/x509-cert"
	Endpoint string
	// Identifiers is the list of KeyConfig.Identifier that identify keys that
	// can be used for the API call.
	Identifiers []string
	// Maximum allowed validity period in seconds for a certificate signed by
	// this endpoint. If not specified default is infinity.
	MaxValidity uint64
}

// KeyConfig contains information about a particular signing key inside HSM.
type KeyConfig struct {
	// Identifier is a unique name that can be used to refer to this key.
	Identifier string
	// SlotNumber is the slot number in HSM.
	SlotNumber uint
	// UserPinPath is the path to the file that contains the pin to login to the specified slot.
	UserPinPath string
	// KeyLabel is the label of the key on the slot.
	KeyLabel string
	// SessionPoolSize specifies the number of sessions that are opened for this key.
	SessionPoolSize int
	// KeyType specifies the type of key, such as RSA or ECDSA.
	KeyType crypki.PublicKeyAlgorithm

	// Below are configs of the x509 CA cert for this key. Useful when this key will be used
	// for signing x509 certificates.

	// CreateCACertIfNotExist should be set to true if the user wants the x509 CA cert to be created
	// when X509CACertLocation is not specified.
	CreateCACertIfNotExist bool
	// X509CACertLocation is the path to the x509 CA certificate.
	X509CACertLocation string
	// Fields of the CA cert in subject line.
	Country, State, Locality, Organization, OrganizationalUnit, CommonName string
}

// Config defines struct to store configuration fields for crypki.
type Config struct {
	ModulePath        string
	TLSClientAuthMode tls.ClientAuthType
	TLSServerName     string
	TLSServerCertPath string
	TLSServerKeyPath  string
	TLSCACertPath     string
	TLSHost           string
	TLSPort           string
	SignersPerPool    int
	Keys              []KeyConfig
	KeyUsages         []KeyUsage
}

// Parse loads configuration values from input file and returns config object and CA cert.
func Parse(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	cfg := &Config{}
	if err := json.NewDecoder(file).Decode(cfg); err != nil {
		return nil, err
	}
	cfg.loadDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate does basic validation on the configuration.
func (c *Config) validate() error {
	if c.TLSServerName == "" {
		return fmt.Errorf("TLSServerName cannot be empty. Please specify it in the config")
	}
	c.TLSServerName = strings.TrimSpace(c.TLSServerName)
	// Do a basic validation on Keys and KeyUsages.
	identifierMap := make(map[string]*KeyConfig, len(c.Keys))
	slotMap := make(map[uint]string, len(c.Keys))
	for idx, key := range c.Keys {
		if _, exist := identifierMap[key.Identifier]; key.Identifier == "" || exist {
			return fmt.Errorf("key %q: require a unique name for Identifier field", key.Identifier)
		}
		identifierMap[key.Identifier] = &c.Keys[idx]

		if key.UserPinPath == "" {
			return fmt.Errorf("key %q: require the pin code file path for slot number #%d", key.Identifier, key.SlotNumber)
		}
		if cachedPinPath, exist := slotMap[key.SlotNumber]; exist && key.UserPinPath != cachedPinPath {
			return fmt.Errorf("key %q: unmatched pin code path for slot number #%d", key.Identifier, key.SlotNumber)
		}
		slotMap[key.SlotNumber] = key.UserPinPath

		if key.CreateCACertIfNotExist && key.X509CACertLocation == "" {
			return fmt.Errorf("key %q: CA cert is supposed to be created if it doesn't exist but X509CACertLocation is not specified", key.Identifier)
		}

		if key.KeyType < crypki.RSA || key.KeyType > crypki.ECDSA {
			return fmt.Errorf("key %q: invalid Key type specified", key.Identifier)
		}
	}

	for _, ku := range c.KeyUsages {
		if _, ok := endpoints[ku.Endpoint]; !ok {
			return fmt.Errorf("unknown endpoint %q", ku.Endpoint)
		}
		// Check that all key identifiers are defined in Keys,
		// and all keys used for "/sig/x509-cert" have x509 CA cert configured.
		for _, id := range ku.Identifiers {
			if key, exist := identifierMap[id]; exist {
				if ku.Endpoint == X509CertEndpoint && key.X509CACertLocation == "" {
					return fmt.Errorf("key %q: key is used to sign x509 certs, but X509CACertLocation is not specified", id)
				}
				continue
			}
			return fmt.Errorf("key identifier %q not found for endpoint %q", id, ku.Endpoint)
		}
	}
	return nil
}

// loadDefaults assigns default values to missing configuration fields.
func (c *Config) loadDefaults() {
	if strings.TrimSpace(c.ModulePath) == "" {
		c.ModulePath = defaultModulePath
	}
	if strings.TrimSpace(c.TLSServerCertPath) == "" {
		c.TLSServerCertPath = defaultTLSServerCertPath
	}
	if strings.TrimSpace(c.TLSServerKeyPath) == "" {
		c.TLSServerKeyPath = defaultTLSServerKeyPath
	}
	if strings.TrimSpace(c.TLSCACertPath) == "" {
		c.TLSCACertPath = defaultTLSCACertPath
	}
	if c.SignersPerPool == 0 {
		c.SignersPerPool = defaultPoolSize
	}
	if strings.TrimSpace(c.TLSHost) == "" {
		c.TLSHost = defaultTLSHost
	}
	if strings.TrimSpace(c.TLSPort) == "" {
		c.TLSPort = defaultTLSPort
	}
	for i := range c.Keys {
		if c.Keys[i].KeyType == 0 {
			c.Keys[i].KeyType = defaultKeyType
		}
		if c.Keys[i].SessionPoolSize == 0 {
			c.Keys[i].SessionPoolSize = defaultPoolSize
		}
	}
}
