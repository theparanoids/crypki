// Copyright 2024 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package utils

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

const defaultMemPollInterval = 60 * time.Minute

// MemCertReloader reloads the (key, cert) pair by invoking the callback functions
// getter.
type MemCertReloader struct {
	mu     sync.RWMutex
	getter func() ([]byte, []byte, error)
	cert   *tls.Certificate

	logger       func(fmt string, args ...interface{})
	once         sync.Once
	stop         chan struct{}
	pollInterval time.Duration
}

// GetCertificate returns the latest known certificate and can be assigned to the
// GetCertificate member of the TLS config. For http.server use.
func (w *MemCertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return w.GetLatestCertificate()
}

// GetClientCertificate returns the latest known certificate and can be assigned to the
// GetClientCertificate member of the TLS config. For http.client use.
func (w *MemCertReloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return w.GetLatestCertificate()
}

// GetLatestCertificate returns the latest known certificate.
func (w *MemCertReloader) GetLatestCertificate() (*tls.Certificate, error) {
	w.mu.RLock()
	c := w.cert
	w.mu.RUnlock()
	return c, nil
}

// Close stops the background refresh.
func (w *MemCertReloader) Close() error {
	w.once.Do(func() {
		close(w.stop)
	})
	return nil
}

// Reload reloads the certificate into the memory cache when the certificate is updated and valid.
func (w *MemCertReloader) Reload() error {
	cb, kb, err := w.getter()
	if err != nil {
		return fmt.Errorf("failed to get the certificate and private key, %v", err)
	}

	if err := ValidateCertExpiry(cb, time.Now()); err != nil {
		return fmt.Errorf("failed to validate certicate, %v", err)
	}

	cert, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		return fmt.Errorf("failed to parse the certificate and private key, %v", err)
	}

	if w.cert != nil {
		if subtle.ConstantTimeCompare(cert.Certificate[0], w.cert.Certificate[0]) == 1 {
			return nil
		}
	}

	w.mu.Lock()
	w.cert = &cert
	w.mu.Unlock()
	w.logger("certs reloaded at %v", time.Now())
	return nil
}

func (w *MemCertReloader) pollRefresh() {
	poll := time.NewTicker(w.pollInterval)
	defer poll.Stop()
	for {
		select {
		case <-poll.C:
			if err := w.Reload(); err != nil {
				w.logger("cert reload error: %v\n", err)
			}
		case <-w.stop:
			return
		}
	}
}

// CertReloadConfig contains the config for cert reload.
type CertReloadConfig struct {
	// CertKeyGetter gets the certificate and the private key.
	CertKeyGetter func() ([]byte, []byte, error)
	Logger        func(fmt string, args ...interface{})
	PollInterval  time.Duration
}

// NewCertReloader returns a MemCertReloader that reloads the (key, cert) pair whenever
// the cert file changes on the filesystem.
func NewCertReloader(config CertReloadConfig) (*MemCertReloader, error) {
	if config.Logger == nil {
		config.Logger = log.Printf
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultMemPollInterval
	}

	var getter func() (cert []byte, key []byte, _ error)

	if config.CertKeyGetter == nil {
		return nil, errors.New("no getter function found in the config")
	}

	if config.CertKeyGetter != nil {
		getter = config.CertKeyGetter
	}

	r := &MemCertReloader{
		getter:       getter,
		logger:       config.Logger,
		pollInterval: config.PollInterval,
		stop:         make(chan struct{}, 10),
	}
	// load once to ensure cert is good.
	if err := r.Reload(); err != nil {
		return nil, err
	}
	go r.pollRefresh()
	return r, nil
}

// ValidateCertExpiry validates the certificate expiry.
func ValidateCertExpiry(certPEM []byte, now time.Time) error {
	if len(bytes.TrimSpace(certPEM)) == 0 {
		return errors.New("certificate is empty")
	}
	for {
		der, rest := pem.Decode(certPEM)
		cp, err := x509.ParseCertificate(der.Bytes)
		if err != nil {
			return err
		}
		if now.Before(cp.NotBefore) || now.After(cp.NotAfter) {
			return fmt.Errorf("invalid certificate, NotBefore: %v, NotAfter: %v, Now: %v", cp.NotBefore, cp.NotAfter, now)
		}
		if len(bytes.TrimSpace(rest)) == 0 {
			return nil
		}
		certPEM = rest
	}
}
