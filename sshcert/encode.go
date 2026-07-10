// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package sshcert

import (
	"fmt"
	"time"

	"github.com/theparanoids/crypki/proto"
	"golang.org/x/crypto/ssh"
)

var supportAlgoNames = map[string]struct{}{
	ssh.KeyAlgoRSA:        {},
	ssh.KeyAlgoDSA:        {}, //nolint:staticcheck // we intentionally support DSA
	ssh.KeyAlgoECDSA256:   {},
	ssh.KeyAlgoECDSA384:   {},
	ssh.KeyAlgoECDSA521:   {},
	ssh.KeyAlgoSKECDSA256: {},
	ssh.KeyAlgoED25519:    {},
	ssh.KeyAlgoSKED25519:  {},
}

const defaultBackdateSeconds = 3600

// DecodeRequest process the SSHCertificateSigningRequest and returns an (unsigned) SSH certificate.
func DecodeRequest(req *proto.SSHCertificateSigningRequest, sshCertType uint32) (*ssh.Certificate, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.GetPublicKey()))
	if err != nil {
		return nil, fmt.Errorf("bad public key: %v", err)
	}

	if _, ok := supportAlgoNames[publicKey.Type()]; !ok {
		return nil, fmt.Errorf("bad public key type: %v", publicKey.Type())
	}

	// Backdate start time as the current system clock may be ahead of other running systems.
	backdateSeconds := req.GetBackdateSeconds()
	if backdateSeconds == 0 {
		backdateSeconds = defaultBackdateSeconds
	}
	start := uint64(time.Now().Unix())
	end := start + req.GetValidity()
	start -= backdateSeconds

	return &ssh.Certificate{
		KeyId:           req.GetKeyId(),
		CertType:        sshCertType,
		ValidPrincipals: req.GetPrincipals(),
		Key:             publicKey,
		ValidAfter:      start,
		ValidBefore:     end,
		Permissions: ssh.Permissions{
			Extensions:      req.GetExtensions(),
			CriticalOptions: req.GetCriticalOptions(),
		},
	}, nil
}
