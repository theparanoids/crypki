// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package sshcert

import (
	"fmt"
	"time"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/proto"
	"golang.org/x/crypto/ssh"
)

var supportAlgoNames = map[string]struct{}{
	ssh.KeyAlgoRSA:        {},
	ssh.KeyAlgoDSA:        {},
	ssh.KeyAlgoECDSA256:   {},
	ssh.KeyAlgoECDSA384:   {},
	ssh.KeyAlgoECDSA521:   {},
	ssh.KeyAlgoSKECDSA256: {},
	ssh.KeyAlgoED25519:    {},
	ssh.KeyAlgoSKED25519:  {},
}

// DecodeRequest process the SSHCertificateSigningRequest and returns an (unsigned) SSH certificate.
func DecodeRequest(req *proto.SSHCertificateSigningRequest, sshCertType uint32, keyP crypki.KeyIDProcessor) (*ssh.Certificate, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.GetPublicKey()))
	if err != nil {
		return nil, fmt.Errorf("bad public key: %v", err)
	}

	if _, ok := supportAlgoNames[publicKey.Type()]; !ok {
		return nil, fmt.Errorf("bad public key type: %v", publicKey.Type())
	}

	// Backdate start time by one hour as the current system clock may be ahead of other running systems.
	start := uint64(time.Now().Unix())
	end := start + req.GetValidity()
	start -= 3600

	keyID, err := keyP.Process(req.GetKeyId())
	if err != nil {
		return nil, fmt.Errorf("unable to process key id: %v", err)
	}

	return &ssh.Certificate{
		KeyId:           keyID,
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
