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
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	p11 "github.com/miekg/pkcs11"

	"github.com/theparanoids/crypki/config"
)

// secureBuffer cached an array of bytes as secret.
// It has a `clear` method to overwrite secret with random data.
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
		err = errors.New("makeSigner: error in Login: " + err.Error())
		err2 := context.CloseSession(session)
		// append CloseSession error to Login error
		if err2 != nil {
			return 0, errors.New(err.Error() + ", CloseSession: " + err2.Error())
		}
		return 0, err
	}
	return session, nil
}

type loginOption interface {
	config(map[uint]*secureBuffer) loginHelper
}

// getLoginSessions opens the PKCS11 login session for all keys in the configuration.
// The pin codes used to login are stored in the secure buffer and are overwritten with random data just before function
// returns.
func getLoginSessions(p11ctx PKCS11Ctx, keys []config.KeyConfig, opts ...loginOption) (map[uint]p11.SessionHandle, error) {
	login := make(map[uint]p11.SessionHandle)
	keyMap := make(map[uint]*secureBuffer)
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
		// config validation makes sure the pin code paths are equal for the same slot.
		if _, exist := keyMap[key.SlotNumber]; !exist {
			pin, err := helper.getUserPinCode(key.UserPinPath)
			if err != nil {
				return nil, fmt.Errorf("unable to read user pin for key with identifier %q, pin path: %v, err: %v", key.Identifier, key.UserPinPath, err)
			}
			keyMap[key.SlotNumber] = pin
			session, err := openLoginSession(p11ctx, key.SlotNumber, pin.get())
			if err != nil {
				return nil, fmt.Errorf("failed to create a login session for key with identifier %q, pin path: %v, err: %v", key.Identifier, key.UserPinPath, err)
			}
			login[key.SlotNumber] = session
		}
	}
	return login, nil
}

// getUserPinCode reads the pin code from the path and stores the pin code into the secure buffer.
func getUserPinCode(path string) (*secureBuffer, error) {
	pin, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("Failed to open pin file: " + err.Error())
	}
	return newSecureBuffer(pin), nil
}
