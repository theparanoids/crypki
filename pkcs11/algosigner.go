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
	"crypto"
	"crypto/x509"
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
)

type sshAlgorithmSigner struct {
	algorithm string
	signer    ssh.AlgorithmSigner
}

func (s *sshAlgorithmSigner) PublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}

func (s *sshAlgorithmSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.signer.SignWithAlgorithm(rand, data, s.algorithm)
}

func getSignatureAlgorithm(publicAlgo x509.PublicKeyAlgorithm, signAlgo x509.SignatureAlgorithm) (algorithm string, err error) {
	switch publicAlgo {
	case x509.RSA:
		{
			switch signAlgo {
			case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384:
				err = errors.New("public key algo & signature algo mismatch, unable to get AlgorithmSigner")
			case x509.SHA1WithRSA:
				algorithm = ssh.SigAlgoRSA
			case x509.SHA512WithRSA:
				algorithm = ssh.SigAlgoRSASHA2512
			case x509.SHA256WithRSA:
				algorithm = ssh.SigAlgoRSASHA2256
			default:
				algorithm = ssh.SigAlgoRSASHA2256
			}
		}
	case x509.ECDSA:
		// For ECDSA public algorithm, signature algo does not exist. We pass in
		// empty algorithm & the crypto library will ensure the right algorithm is chosen
		// for signing the cert.
		return
	default:
		err = errors.New("public key algorithm not supported")
	}
	return
}

func newAlgorithmSignerFromSigner(signer crypto.Signer, publicAlgo x509.PublicKeyAlgorithm, signAlgo x509.SignatureAlgorithm) (ssh.Signer, error) {
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, err
	}
	algorithmSigner, ok := sshSigner.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("unable to cast to ssh.AlgorithmSigner")
	}
	algorithm, err := getSignatureAlgorithm(publicAlgo, signAlgo)
	if err != nil {
		return nil, err
	}
	s := sshAlgorithmSigner{
		signer:    algorithmSigner,
		algorithm: algorithm,
	}
	return &s, nil
}
