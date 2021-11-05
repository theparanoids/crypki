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
	"errors"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/theparanoids/crypki"
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

func getSignatureAlgorithm(publicAlgo crypki.PublicKeyAlgorithm, signAlgo crypki.SignatureAlgorithm) (algorithm string, err error) {
	switch publicAlgo {
	case crypki.RSA:
		{
			switch signAlgo {
			case crypki.ECDSAWithSHA256, crypki.ECDSAWithSHA384:
				err = errors.New("public key algo & signature algo mismatch, unable to get AlgorithmSigner")
			case crypki.SHAWithRSA:
				algorithm = ssh.SigAlgoRSA
			case crypki.SHA512WithRSA:
				algorithm = ssh.SigAlgoRSASHA2512
			case crypki.SHA256WithRSA:
				algorithm = ssh.SigAlgoRSASHA2256
			default:
				algorithm = ssh.SigAlgoRSASHA2256
			}
		}
	case crypki.ECDSA:
		{
			// For ECDSA public algorithm, signature algo does not exist. We pass in
			// empty algorithm & the upstream code will ensure the right algorithm is chosen
			// for signing the cert.
			switch signAlgo {
			case crypki.ECDSAWithSHA256, crypki.ECDSAWithSHA384:
				return
			case crypki.SHAWithRSA, crypki.SHA256WithRSA, crypki.SHA512WithRSA:
				err = errors.New("public key algo & signature algo mismatch, unable to get AlgorithmSigner")
			default:
			}
		}
	default:
		err = errors.New("public key algorithm not supported")
	}
	return
}

func newAlgorithmSignerFromSigner(signer crypto.Signer, publicAlgo crypki.PublicKeyAlgorithm, signAlgo crypki.SignatureAlgorithm) (ssh.Signer, error) {
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
