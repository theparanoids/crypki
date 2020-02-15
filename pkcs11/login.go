package pkcs11

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"

	p11 "github.com/miekg/pkcs11"

	"github.com/yahoo/crypki/config"
)

// secureBuffer cached an array of bytes as secret.
// It has a `clear` method to overwrite secret with random data to reduce data breach.
type secureBuffer struct {
	secret []byte
}

func (b *secureBuffer) get() string {
	return string(b.secret)
}

func (b *secureBuffer) clear() {
	_, _ = rand.Read(b.secret)
}

func newSecureBuffer(secret []byte) *secureBuffer {
	return &secureBuffer{secret: bytes.TrimSpace(secret)}
}

type loginHelper interface {
	getUserPinCode(string) (*secureBuffer, error)
}

type defaultHelper struct{}

func (h *defaultHelper) getUserPinCode(path string) (*secureBuffer, error) {
	return getUserPinCode(path)
}

// openLoginSession opens a PKCS11 session and tries to log in.
func openLoginSession(context PKCS11Ctx, slot uint, userPin string) (p11.SessionHandle, error) {
	session, err := context.OpenSession(slot, p11.CKF_SERIAL_SESSION)
	if err != nil {
		return 0, errors.New("makeLoginSession: error in OpenSession: " + err.Error())
	}

	if err = context.Login(session, p11.CKU_USER, userPin); err != nil {
		context.CloseSession(session)
		return 0, errors.New("makeSigner: error in Login: " + err.Error())
	}
	return session, nil
}

type loginOption interface {
	config(map[uint]*secureBuffer) loginHelper
}

// getLoginSessions opens the PKCS11 login session for all keys in the configuration.
// If there is a login session for the slot, an error will be returned if the pin code doesn't match the logged-in session.
// The pin codes used to login are stored in the secure buffer and overwrite with random data after function returned.
func getLoginSessions(p11ctx PKCS11Ctx, keys []config.KeyConfig, opts ...loginOption) (map[uint]p11.SessionHandle, error) {
	login := make(map[uint]p11.SessionHandle)
	keyMap := map[uint]*secureBuffer{}
	defer func() {
		for _, buffer := range keyMap {
			buffer.clear()
		}
	}()

	// `helper` provides the `getUserPinCode` method to get the pin code from input path.
	// This helper is also used to help unit test to check the status of the function-scoped variable.
	helper := loginHelper(&defaultHelper{})
	for _, opt := range opts {
		helper = opt.config(keyMap)
	}

	for _, key := range keys {
		pin, err := helper.getUserPinCode(key.UserPinPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read user pin for key with identifier %q, pin path: %v, err: %v", key.Identifier, key.UserPinPath, err)
		}
		if cachedPin, exist := keyMap[key.SlotNumber]; !exist {
			keyMap[key.SlotNumber] = pin
			session, err := openLoginSession(p11ctx, key.SlotNumber, pin.get())
			if err != nil {
				return nil, fmt.Errorf("failed to create a login session for key with identifier %q, pin path: %v, err: %v", key.Identifier, key.UserPinPath, err)
			}
			login[key.SlotNumber] = session
		} else if !bytes.Equal(cachedPin.secret, pin.secret) {
			err := fmt.Errorf("user already logged into slot %d with other pin code", key.SlotNumber)
			return nil, fmt.Errorf("failed to create a login session for key with identifier %q, pin path: %v, err: %v", key.Identifier, key.UserPinPath, err)
		}
	}
	return login, nil
}

// getUserPinCode reads the pin code from the path and stores the pin code into the secure buffer.
func getUserPinCode(path string) (*secureBuffer, error) {
	pin, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New("Failed to open pin file: " + err.Error())
	}
	return newSecureBuffer(pin), nil
}
