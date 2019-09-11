// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package sshcert

import (
	"fmt"
	"time"

	"github.com/yahoo/crypki/proto"
	"golang.org/x/crypto/ssh"
)

// DecodeRequest process the SSHCertificateSigningRequest and returns an (unsigned) SSH certificate.
func DecodeRequest(req *proto.SSHCertificateSigningRequest, sshCertType uint32) (*ssh.Certificate, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.GetPublicKey()))
	if err != nil {
		return nil, fmt.Errorf("bad public key: %v", err)
	}

	// Backdate start time by one hour as the current system clock may be ahead of other running systems.
	start := uint64(time.Now().Unix())
	end := start + req.GetValidity()
	start -= 3600

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
