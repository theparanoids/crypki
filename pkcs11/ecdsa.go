package pkcs11

import (
	"crypto"
	"errors"

	p11 "github.com/miekg/pkcs11"
)

func publicECDSA(s *p11Signer) crypto.PublicKey {
	// TODO: implement
	panic("not implemented yet")
}

func signDataECDSA(ctx PKCS11Ctx, session p11.SessionHandle, hsmPrivateObject p11.ObjectHandle, data []byte, opts crypto.SignerOpts) ([]byte, error) {
	// TODO: implement
	return nil, errors.New("not implemented yet")
}
