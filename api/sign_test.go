// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package api

import (
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/yahoo/crypki/config"
	"golang.org/x/crypto/ssh"
)

const (
	testGoodcsrRsa = `-----BEGIN CERTIFICATE REQUEST-----
MIICpjCCAY4CAQAwYTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQswCQYDVQQH
DAJYWDELMAkGA1UECgwCWFgxCzAJBgNVBAsMAlhYMQswCQYDVQQDDAJYWDERMA8G
CSqGSIb3DQEJARYCWFgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDC
P3r7L/sLOBEAbnjLrAXcf24faKQquBJ27gQUns8iKpVdZaSQ0BRTnZ1iH/zU5o1e
o15aTTXrMKFgZMjaOPtYl5nObqKyi24FGCzL/8T6npcjjtMc61+Iowu+w9CkxVgs
7itkHLMI96tvtyEY67YAhI47I/KJYhHKXZuOA2FaM0uRYWgUHTAJw6WxSgHq+XoF
E/Geesa37If1YmdxOUFtkWF6KciYTtHP1qrjnSVhd+TjWfUt0ZVPJOd83Z4UVPY+
J6HISAlYDuMFYdPMe4SKwV4uEBq3PJWlLRi9EsLlG8PqfR0Bm+tzH39/H0PyqIzl
hELnGV4DbbX6AfaFxREjAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAYn4POSuT
LaUJzdshjiY0oRy1ufa8h+sP0ZVuLGzgT9/I9MhkULXjNVJPpbsradkvvZk5yGcr
HwBXI5fnHkYyXp/NhT1h2e5tOc/FKLzZwK9uX+++AIh7ZD3v3agTswTZt2/UR5BD
+aJXk1ee1UtXjIcliRrvm6JJkSuWx5itipPiMNgS7jy0QHNzMrR6DvI+WVQx4FVa
PwyKUayqdMOmYwl/raO1S8jQ/3WUexteF+lrOxmTmcUuaF07slKCP5EO5eJ3+VRg
ZcYyckIvUQU5TIup0+hUFA+ar9yfA2WaDYqHuz3lCk5PN4gUgymU4NCMvqkZ8HJJ
k160FxGUa2zGqw==
-----END CERTIFICATE REQUEST-----`
	// ECDSA Elliptic curve: secp521r1
	testGoodcsrEc = `-----BEGIN CERTIFICATE REQUEST-----
MIIBpTCCAQYCAQAwYTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlhYMQswCQYDVQQH
DAJYWDELMAkGA1UECgwCWFgxCzAJBgNVBAsMAlhYMQswCQYDVQQDDAJYWDERMA8G
CSqGSIb3DQEJARYCWFgwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABADW390eU0gT
Uv3RmQoMc+T3MhCDJNZbw9OaCr2LyoJluFpH5LpRLPk8jqZUNSxdeDGdUEPqdhta
C/PUGbEx6UqtEACiR28dz/7YQAqfyVv4GXaFuacIZZj8JDwyL0lL1sg7WA8RSYMA
7xbpk2DXGetWa8z4K/I7OBYZ2/OYDGgSW1oVuaAAMAoGCCqGSM49BAMCA4GMADCB
iAJCAf+ezR8UoGvQ0X+OX1rONp0WFtHC6pbE03jVvcOHHKnOKRW1ivU2IpKvXbz8
UDqinTa6CHKDSjI7RweJHczdBus1AkIB376Ba4qvP5IAp+3JYHA4PDLtSJoTLxrJ
jfOwXe2T9BIwzSu8EH9adQhFt1tH/yy5KTK3H5556OFOTSzxh2zfLa4=
-----END CERTIFICATE REQUEST-----`
	testGoodcsrED25519 = `-----BEGIN CERTIFICATE REQUEST-----
MIGbME8CAQAwHDEaMBgGA1UEAxMRZm9vLmJhci55YWhvby5jb20wKjAFBgMrZXAD
IQAPCN2lUJcxG5UYvuwnxZQJkS6MmRDfaLgqcUPfgx6LtKAAMAUGAytlcANBAFMD
njJnZ795o9DbEhiHuUVEu2WUBXd32vPd+Ij55lHdTcCb9hQcAMAP3K0xdyH8V8E2
6b9a0A8/oKsiOAU9mgA=
-----END CERTIFICATE REQUEST-----`
	testGoodRsaPubKey   = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3qVQkPbXzYzykUomIP9q/ZYyIyKFyYZt/7qZ5fIsnfFBmJAbRMiQCXxKUcM8EkY4MO4d7ujePdLZRwPz+IakOhpvldIXJGgURMNiVbGpXFNS9HHOFnvFdiss6piu7oG9J1cMaR3XqnV5waiYSEQ+w1e/ZGcGFmq4Bc/ubeFU/kPG110pXCT+Ka6nSUI2p7zg7tEH9hOx8oWB1RoVFlPzGr1pO+pwNT6SyPK/pSCTlR3iiv84C70DSh/uKe0Hl3R0i/ebJrHNy5HaIL4hcB7bUXgyko6tU+zOaL0kVjHVNninq/wu9YIG5Q3CL6Or6+RbWkI5b3Rfxh1cuCxHv//RV XX@XX`
	testGoodDsaPubKey   = `ssh-dss AAAAB3NzaC1kc3MAAACBAJO2OS5J02GNCTRdHkkCKnrAM6ZJkyHsvlixWN+16ahzqZD7ijdQwiIofchTpqAsKgXPLH3OhCMvItDrvsJ56SNbP1RlW9qcPix94Ar4xaiW5kqngf0AallzVO1yjyVA0vtjzGBiM0ShzMGYogj1+jOsjgu2/B/FvGb2gIAc/l1lAAAAFQCZdAPNrWBZ92WeSmgL42iQZqKiwwAAAIAyMcUFJYzB+CDZ5aifPYzWPyrHfi/DhHmiY4pDAjFnZUWB6N+Heo1ovITVPLL7coFwLcv1PCvAJ7H+2BPtx7OMzicfAB2OustgzMfznOeUXVtFvA4jaaBP1x/BTrH4THz3gTg/lr6kBpsb/nHzBCLRXjGxsXV/GLQfVvBqVGQruAAAAIAhD56FQ9iNOMHiK+Lin1tF5f/kHFdUMIO1DRodv2ueBTTgXjcZ28i5KVCEuifQ8e9QFy7Za1NePAc1R0MwDoytyirK4IWFZCn0X1nHd1DRuw+0yxUOwwk/HyjC5myo7wf3ZNcjzBu5Hd56POc6XtIHY88PX8dsGyzKGv5J3ops1A== XXX@X2VD2JLHTDD`
	testGoodEcdsaPubKey = `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGbEX631frylkElDpZzmc2use3n/kCO7WXI07D1DYGutOd2F1ZTAcqCd2jzWzjNurS2Y2rROJP1roeDTAm6p8jI= XXX@XXVD2JLHTDD`
	testGoodKeyID       = `prins=Bob, crTime=20200529T010015, host=host.XXX.com, reqU=Bob, reqIP=1.2.3.4, transID=6431f24e`
)

var (
	x509keyUsage = map[string]map[string]bool{
		config.X509CertEndpoint: {"x509id": true},
	}

	sshkeyUsage = map[string]map[string]bool{
		config.SSHUserCertEndpoint: {"sshuserid": true},
		config.SSHHostCertEndpoint: {"sshhostid": true},
	}

	blobkeyUsage = map[string]map[string]bool{
		config.BlobEndpoint: {"blobid": true},
	}

	combineKeyUsage = map[string]map[string]bool{
		config.X509CertEndpoint:    {"x509id1": true, "x509id2": false},
		config.SSHHostCertEndpoint: {"sshhostid1": true, "sshhostid2": false},
		config.SSHUserCertEndpoint: {"sshuserid1": true, "sshuserid2": false},
		config.BlobEndpoint:        {"blobid1": true, "blobid2": false},
	}
)

type mockSigningServiceParam struct {
	KeyUsages   map[string]map[string]bool
	MaxValidity map[string]uint64
	sendError   bool
}

type mockBadCertSign struct {
}

func (mbcs *mockBadCertSign) GetSSHCertSigningKey(keyIdentifier string) ([]byte, error) {
	return nil, errors.New("bad message")
}
func (mbcs *mockBadCertSign) SignSSHCert(cert *ssh.Certificate, keyIdentifier string) ([]byte, error) {
	return nil, errors.New("bad message")
}
func (mbcs *mockBadCertSign) GetX509CACert(keyIdentifier string) ([]byte, error) {
	return nil, errors.New("bad message")
}
func (mbcs *mockBadCertSign) SignX509Cert(cert *x509.Certificate, keyIdentifier string) ([]byte, error) {
	return nil, errors.New("bad message")
}
func (mbcs *mockBadCertSign) GetBlobSigningPublicKey(keyIdentifier string) ([]byte, error) {
	return nil, errors.New("bad message")
}
func (mbcs *mockBadCertSign) SignBlob(digest []byte, opts crypto.SignerOpts, keyIdentifier string) ([]byte, error) {
	return nil, errors.New("bad message")
}

type mockGoodCertSign struct {
}

func (mgcs *mockGoodCertSign) GetSSHCertSigningKey(keyIdentifier string) ([]byte, error) {
	return []byte("good ssh signing key"), nil
}
func (mgcs *mockGoodCertSign) SignSSHCert(cert *ssh.Certificate, keyIdentifier string) ([]byte, error) {
	return []byte("good ssh cert"), nil
}
func (mgcs *mockGoodCertSign) GetX509CACert(keyIdentifier string) ([]byte, error) {
	return []byte("good x509 ca cert"), nil
}
func (mgcs *mockGoodCertSign) SignX509Cert(cert *x509.Certificate, keyIdentifier string) ([]byte, error) {
	return []byte("good x509 cert"), nil
}
func (mgcs *mockGoodCertSign) GetBlobSigningPublicKey(keyIdentifier string) ([]byte, error) {
	return []byte("good blob signing key"), nil
}
func (mgcs *mockGoodCertSign) SignBlob(digest []byte, opts crypto.SignerOpts, keyIdentifier string) ([]byte, error) {
	return []byte("good blob signature"), nil
}

// InitMockSigningService initializes a mock signing service which implements mock functions
func initMockSigningService(mssp mockSigningServiceParam) *SigningService {
	ss := &SigningService{}
	ss.KeyUsages = mssp.KeyUsages
	ss.MaxValidity = mssp.MaxValidity
	if mssp.sendError {
		ss.CertSign = &mockBadCertSign{}
	} else {
		ss.CertSign = &mockGoodCertSign{}
	}
	return ss
}

func TestCheckValidity(t *testing.T) {
	t.Parallel()
	table := map[string]struct {
		validity    uint64
		maxValidity uint64
		expectErr   bool
	}{
		"valid": {
			validity:    3600,
			maxValidity: 36000,
			expectErr:   false,
		},
		"equal": {
			validity:    3600,
			maxValidity: 3600,
			expectErr:   false,
		},
		"no maxValidity": {
			validity:    3600,
			maxValidity: 0,
			expectErr:   false,
		},
		"no validity": {
			validity:    0,
			maxValidity: 0,
			expectErr:   true,
		},
		"validity greater than maxValidity": {
			validity:    3601,
			maxValidity: 3600,
			expectErr:   true,
		},
	}
	for name, tt := range table {
		err := checkValidity(tt.validity, tt.maxValidity)
		if tt.expectErr {
			if err == nil {
				t.Errorf("expected error for invalid test %v, got nil", name)
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error for %v, err: %v", name, err)
				continue
			}
		}
	}
}
