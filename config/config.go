// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	defaultModulePath        = "/opt/utimaco/lib/libcs_pkcs11_R2.so"
	defaultTLSServerCertPath = "/opt/crypki/server.crt"
	defaultTLSCACertPath     = "/opt/crypki/ca.crt"
	defaultTLSServerKeyPath  = "/opt/crypki/server.key"
	defaultTLSHost           = ""
	defaultTLSPort           = "4443"
	defaultPoolSize          = 2
	defaultKeyType           = x509.RSA
	defaultSignatureAlgo     = x509.SHA256WithRSA
	defaultHealthCheckKeyID  = "ssh-user-key"

	defaultShutdownOnSigningFailureConsecutiveCount    = 4
	defaultShutdownOnSigningFailureTimerDurationSecond = 60
	defaultShutdownOnSigningFailureTimerCount          = 10

	defaultIdleTimeout  = 30
	defaultReadTimeout  = 10
	defaultWriteTimeout = 10

	// X509CertEndpoint specifies the endpoint for signing X509 certificate.
	X509CertEndpoint = "/sig/x509-cert"
	// SSHUserCertEndpoint specifies the endpoint for signing SSH user certificate.
	SSHUserCertEndpoint = "/sig/ssh-user-cert"
	// SSHHostCertEndpoint specifies the endpoint for signing SSH host certificate.
	SSHHostCertEndpoint = "/sig/ssh-host-cert"
	// BlobEndpoint specifies the endpoint for raw signing.
	BlobEndpoint = "/sig/blob"
	// DefaultPKCS11Timeout specifies the max time required by HSM to sign a cert.
	DefaultPKCS11Timeout = 10 * time.Second
)

var endpoints = map[string]bool{
	X509CertEndpoint:    true,
	SSHUserCertEndpoint: true,
	SSHHostCertEndpoint: true,
	BlobEndpoint:        true,
}

// HealthCheck specifies configs related to healthcheck listener.
type HealthCheck struct {
	// Enabled specifies whether healthcheck listener should be enabled.
	Enabled bool
	// Address specifies the address for the http listener.
	Address string
	// KeyID specifies the identifier of the key to be used by
	// healthcheck listener.
	KeyID string
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
	// PrioritySchedulingEnabled indicates whether to schedule requests based on the priority/urgency of the request
	// being received. If disabled, all requests are treated with equal priority.
	PrioritySchedulingEnabled bool
}

// KeyConfig contains information about a particular signing key inside HSM.
type KeyConfig struct {
	// Identifier is a unique name that can be used to refer to this key.
	Identifier string
	// SlotNumber is the slot number in HSM.
	SlotNumber uint
	// TokenLabel is the token label in HSM. If this value is specified, SlotNumber is specified by this.
	TokenLabel string
	// UserPinPath is the path to the file that contains the pin to login to the specified slot.
	UserPinPath string
	// KeyLabel is the label of the key on the slot.
	KeyLabel string
	// SessionPoolSize specifies the number of sessions that are opened for this key.
	SessionPoolSize int
	// KeyType specifies the type of key, such as RSA or ECDSA.
	KeyType x509.PublicKeyAlgorithm
	// SignatureAlgo specifies the type of signature hash function such as SHA256WithRSA or ECDSAWithSHA384.
	SignatureAlgo x509.SignatureAlgorithm

	// Below are configs of x509 extensions for this key. Useful when this key will be used
	// for signing x509 certificates.

	// OCSPServers are the locations of OCSP responders.
	OCSPServers []string
	// CRLDistributionPoints are the URIs of CRL distribution endpoints.
	CRLDistributionPoints []string

	// Below are configs of the x509 CA cert for this key. Useful when this key will be used
	// for signing x509 certificates.

	// CreateCACertIfNotExist should be set to true if the user wants the x509 CA cert to be created
	// when X509CACertLocation is not specified.
	CreateCACertIfNotExist bool
	// X509CACertLocation is the path to the x509 CA certificate.
	X509CACertLocation string
	// Fields of the CA cert in subject line.
	Country, State, Locality, Organization, OrganizationalUnit, CommonName string
	// The validity time period of the CA cert, which is specified in seconds.
	ValidityPeriod uint64
}

// Config defines struct to store configuration fields for crypki.
type Config struct {
	ModulePath        string
	TLSClientAuthMode tls.ClientAuthType
	TLSServerCertPath string
	TLSServerKeyPath  string
	TLSCACertPath     string
	TLSHost           string
	TLSPort           string
	SignersPerPool    int
	Keys              []KeyConfig
	KeyUsages         []KeyUsage
	HealthCheck

	ShutdownOnInternalFailure         bool
	ShutdownOnInternalFailureCriteria struct {
		ReportMode            bool
		ConsecutiveCountLimit uint
		TimerDurationSecond   uint
		TimerCountLimit       uint
	}

	// timeouts used in initialization of http.Server (in seconds)
	IdleTimeout  uint
	ReadTimeout  uint
	WriteTimeout uint
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

// ValidatePinIntegrity checks whether the same slot uses the same pinfile.
func ValidatePinIntegrity(keys []KeyConfig) error {
	slotMap := make(map[uint]string, len(keys))
	for _, key := range keys {
		if cachedPinPath, exist := slotMap[key.SlotNumber]; exist && key.UserPinPath != cachedPinPath {
			return fmt.Errorf("key %q: unmatched pin code path for slot number #%d", key.Identifier, key.SlotNumber)
		}
		slotMap[key.SlotNumber] = key.UserPinPath
	}
	return nil
}

// validate does basic validation on the configuration.
func (c *Config) validate() error {
	// Do a basic validation on Keys and KeyUsages.
	identifierMap := make(map[string]*KeyConfig, len(c.Keys))
	for idx, key := range c.Keys {
		if _, exist := identifierMap[key.Identifier]; key.Identifier == "" || exist {
			return fmt.Errorf("key %q: require a unique name for Identifier field", key.Identifier)
		}
		identifierMap[key.Identifier] = &c.Keys[idx]

		if key.UserPinPath == "" {
			return fmt.Errorf("key %q: require the pin code file path for slot number #%d", key.Identifier, key.SlotNumber)
		}
		if key.CreateCACertIfNotExist && key.X509CACertLocation == "" {
			return fmt.Errorf("key %q: CA cert is supposed to be created if it doesn't exist but X509CACertLocation is not specified", key.Identifier)
		}

		if key.KeyType < x509.RSA || key.KeyType > x509.Ed25519 {
			return fmt.Errorf("key %q: invalid Key type specified", key.Identifier)
		}

		if key.SignatureAlgo < x509.SHA1WithRSA || key.SignatureAlgo > x509.PureEd25519 {
			return fmt.Errorf("key %q: invalid signature hash algo specified", key.Identifier)
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
	if c.HealthCheck.KeyID == "" {
		c.HealthCheck.KeyID = defaultHealthCheckKeyID
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
		if c.Keys[i].SignatureAlgo == 0 {
			c.Keys[i].SignatureAlgo = defaultSignatureAlgo
		}
	}

	if c.ShutdownOnInternalFailureCriteria.ConsecutiveCountLimit == 0 {
		c.ShutdownOnInternalFailureCriteria.ConsecutiveCountLimit = defaultShutdownOnSigningFailureConsecutiveCount
	}
	if c.ShutdownOnInternalFailureCriteria.TimerDurationSecond == 0 {
		c.ShutdownOnInternalFailureCriteria.TimerDurationSecond = defaultShutdownOnSigningFailureTimerDurationSecond
	}
	if c.ShutdownOnInternalFailureCriteria.TimerCountLimit == 0 {
		c.ShutdownOnInternalFailureCriteria.TimerCountLimit = defaultShutdownOnSigningFailureTimerCount
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = defaultIdleTimeout
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = defaultReadTimeout
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = defaultWriteTimeout
	}
}
