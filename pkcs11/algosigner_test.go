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
package pkcs11

import (
	"crypto/x509"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGetSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		pubAlgo   x509.PublicKeyAlgorithm
		signAlgo  x509.SignatureAlgorithm
		want      string
		wantError bool
	}{
		"rsa pub rsa 256 signing": {
			pubAlgo:   x509.RSA,
			signAlgo:  x509.SHA256WithRSA,
			want:      ssh.SigAlgoRSASHA2256,
			wantError: false,
		},
		"rsa pub rsa 512 signing": {
			pubAlgo:   x509.RSA,
			signAlgo:  x509.SHA512WithRSA,
			want:      ssh.SigAlgoRSASHA2512,
			wantError: false,
		},
		"rsa pub sha1 signing": {
			pubAlgo:   x509.RSA,
			signAlgo:  x509.SHA1WithRSA,
			want:      ssh.SigAlgoRSA,
			wantError: false,
		},
		"rsa pub ec signing": {
			pubAlgo:   x509.RSA,
			signAlgo:  x509.ECDSAWithSHA384,
			want:      "",
			wantError: true,
		},
		"rsa pub no signing algo": {
			pubAlgo:   x509.RSA,
			signAlgo:  x509.UnknownSignatureAlgorithm,
			want:      ssh.SigAlgoRSASHA2256,
			wantError: false,
		},
		"ec pub ec sign": {
			pubAlgo:   x509.ECDSA,
			signAlgo:  x509.ECDSAWithSHA384,
			want:      "",
			wantError: false,
		},
		"default pub key algo": {
			pubAlgo:   x509.UnknownPublicKeyAlgorithm,
			signAlgo:  x509.UnknownSignatureAlgorithm,
			want:      "",
			wantError: true,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			got, err := getSignatureAlgorithm(tt.pubAlgo, tt.signAlgo)
			if (err != nil) != tt.wantError {
				t.Errorf("%s: got %s want %s", name, got, tt.want)
			}
			if got != tt.want {
				t.Errorf("%s: got %s want %s", name, got, tt.want)
			}
		})
	}
}
