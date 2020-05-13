// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package sshcert

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
	"time"

	"github.com/yahoo/crypki"
	"github.com/yahoo/crypki/proto"
	"golang.org/x/crypto/ssh"
)

func getSelfSignedCertificate() (ssh.PublicKey, *ssh.Certificate, error) {
	const (
		bit      = 2048
		validity = 3600
	)

	priv, err := rsa.GenerateKey(rand.Reader, bit)
	if err != nil {
		return nil, nil, err
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, nil, err
	}
	start := uint64(time.Now().Unix())
	end := start + validity
	cert := &ssh.Certificate{
		Key:         pub,
		KeyId:       "",
		ValidAfter:  start,
		ValidBefore: end,
		Permissions: ssh.Permissions{},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, nil, err
	}
	return pub, cert, nil
}

func TestDecodeRequest(t *testing.T) {
	t.Parallel()

	pub, cert, err := getSelfSignedCertificate()
	if err != nil {
		t.Fatal(err)
	}

	exts := make(map[string]string)
	exts["permit-pty"] = ""
	exts["permit-X11-forwarding"] = ""
	exts["permit-agent-forwarding"] = ""
	exts["permit-port-forwarding"] = ""
	exts["permit-user-rc"] = ""

	optsIP := make(map[string]string)
	optsIP["source-address"] = "10.11.12.13/32"

	optsIPCmd := make(map[string]string)
	optsIPCmd["source-address"] = "10.11.12.13/32"
	optsIPCmd["force-command"] = "ls -l"

	optsIPCmdTshosts := make(map[string]string)
	optsIPCmdTshosts["source-address"] = "10.11.12.13/32"
	optsIPCmdTshosts["force-command"] = "ls -l"
	optsIPCmdTshosts["touchless-sudo-hosts"] = "a.oath.com,b.verizonmedia.com"

	optsEmpty := make(map[string]string)
	optsEmpty["source-address"] = ""
	optsEmpty["force-command"] = ""
	optsEmpty["touchless-sudo-hosts"] = ""

	testcases := map[string]struct {
		validity uint64
		req      *ssh.Certificate
	}{
		"good-req-user": {
			validity: (12 + 1) * 3600,
			req: &ssh.Certificate{
				CertType:        ssh.UserCert,
				ValidPrincipals: []string{"principal.yahoo.com", "principal.aol.com"},
				Key:             pub,
				KeyId:           "",
			},
		},
		"good-req-user-noPrincs": {
			validity: (12 + 1) * 3600,
			req: &ssh.Certificate{
				CertType: ssh.UserCert,
				Key:      pub,
				KeyId:    "",
			},
		},
		"good-req-user-ext-opt": {
			validity: (12 + 1) * 3600,
			req: &ssh.Certificate{
				CertType:        ssh.UserCert,
				ValidPrincipals: []string{"principal.yahoo.com", "principal.aol.com"},
				Key:             pub,
				KeyId:           "",
				Permissions: ssh.Permissions{
					Extensions:      exts,
					CriticalOptions: optsEmpty,
				},
			},
		},
		"good-req-user-ips": {
			validity: (12 + 1) * 3600,
			req: &ssh.Certificate{
				CertType:        ssh.UserCert,
				ValidPrincipals: []string{"principal.yahoo.com", "principal.aol.com"},
				Key:             pub,
				KeyId:           "",
				Permissions: ssh.Permissions{
					Extensions:      exts,
					CriticalOptions: optsIP,
				},
			},
		},
		"good-req-user-ips-command": {
			validity: (12 + 1) * 3600,
			req: &ssh.Certificate{

				CertType:        ssh.UserCert,
				ValidPrincipals: []string{"principal.yahoo.com", "principal.aol.com"},
				Key:             pub,
				KeyId:           "",
				Permissions: ssh.Permissions{
					Extensions:      exts,
					CriticalOptions: optsIPCmd,
				},
			},
		},
		"good-req-user-ips-command-touchlesshosts": {
			validity: (12 + 1) * 3600,
			req: &ssh.Certificate{

				CertType:        ssh.UserCert,
				ValidPrincipals: []string{"principal.yahoo.com", "principal.aol.com"},
				Key:             pub,
				KeyId:           "",
				Permissions: ssh.Permissions{
					Extensions:      exts,
					CriticalOptions: optsIPCmdTshosts,
				},
			},
		},
		"good-req-host": {
			validity: (12 + 1) * 3600,
			req: &ssh.Certificate{

				CertType: ssh.HostCert,
				Key:      pub,
				KeyId:    "",
			},
		},
		"bad-req-user": {
			validity: (12 + 1) * 3600,
			req: &ssh.Certificate{
				CertType:        ssh.UserCert,
				ValidPrincipals: []string{"principal.yahoo.com", "principal.aol.com"},
				Key:             cert,
				KeyId:           "",
			},
		},
		"bad-req-host": {
			validity: (12 + 1) * 3600,
			req: &ssh.Certificate{

				CertType: ssh.HostCert,
				Key:      cert,
				KeyId:    "",
			},
		},
	}
	for k, tt := range testcases {
		tt := tt // capture range variable - see https://blog.golang.org/subtests
		t.Run(k, func(t *testing.T) {

			cReq := &proto.SSHCertificateSigningRequest{
				Principals:      tt.req.ValidPrincipals,
				PublicKey:       string(ssh.MarshalAuthorizedKey(tt.req.Key)),
				Validity:        tt.validity,
				KeyId:           tt.req.KeyId,
				CriticalOptions: tt.req.Permissions.CriticalOptions,
				Extensions:      tt.req.Extensions,
			}

			expectError := k[0:3] == "bad"
			req, err := DecodeRequest(cReq, tt.req.CertType, &crypki.KeyID{})
			if err != nil {
				if !expectError {
					t.Errorf("unexpected err: %v", err)
				}
				return
			}
			if expectError {
				t.Error("expected error, got none")
				return
			}

			// cannot validate ValidBefore, ValidAfter and KeyId fields because
			// those rely on current timestamp.
			tt.req.ValidBefore = req.ValidBefore
			tt.req.ValidAfter = req.ValidAfter
			tt.req.KeyId = req.KeyId

			if req.ValidBefore-req.ValidAfter != cReq.Validity+3600 {
				t.Errorf("validity mismatch: got: %v, want: %v", req.ValidBefore-req.ValidAfter, cReq.Validity)
				return
			}

			if !reflect.DeepEqual(tt.req, req) {
				t.Errorf("request object mismatch got: \n%+v\n want: \n%+v\n", req, &tt)
				t.Errorf("cert got: \n%+v\n want: \n%+v\n", req, tt.req)
				return
			}

		})
	}

}
