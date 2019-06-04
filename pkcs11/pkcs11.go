// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pkcs11

import (
	"errors"
	"fmt"

	p11 "github.com/miekg/pkcs11"
	"github.com/yahoo/crypki"
)

// PKCS11Ctx interface is added to mock pkcs11.Ctx
// run the following command to generate mock
//go:generate $GOPATH/bin/mockgen -source=pkcs11.go -destination ./mock_pkcs11/mock_pkcs11.go
type PKCS11Ctx interface {
	GetAttributeValue(p11.SessionHandle, p11.ObjectHandle, []*p11.Attribute) ([]*p11.Attribute, error)
	SignInit(p11.SessionHandle, []*p11.Mechanism, p11.ObjectHandle) error
	Sign(p11.SessionHandle, []byte) ([]byte, error)
	Login(p11.SessionHandle, uint, string) error
	GenerateRandom(p11.SessionHandle, int) ([]byte, error)
	FindObjectsInit(sh p11.SessionHandle, temp []*p11.Attribute) error
	FindObjects(sh p11.SessionHandle, max int) ([]p11.ObjectHandle, bool, error)
	FindObjectsFinal(sh p11.SessionHandle) error
	CloseSession(sh p11.SessionHandle) error
	OpenSession(slotID uint, flags uint) (p11.SessionHandle, error)
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetSlotInfo(slotID uint) (p11.SlotInfo, error)
	GetTokenInfo(slotID uint) (p11.TokenInfo, error)
}

// initPKCS11Context initializes PKCS11 context
func initPKCS11Context(modulePath string) (*p11.Ctx, error) {
	context := p11.New(modulePath)

	if context == nil {
		return nil, fmt.Errorf("unable to load PKCS#11 module:" + modulePath)
	}

	err := context.Initialize()
	return context, err
}

func getKey(context PKCS11Ctx, session p11.SessionHandle, label string, keyType uint) (p11.ObjectHandle, error) {
	var noKey p11.ObjectHandle
	if keyType != p11.CKO_PRIVATE_KEY && keyType != p11.CKO_PUBLIC_KEY {
		return noKey, fmt.Errorf("not supported keyType: %v", keyType)
	}
	template := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, keyType),
		p11.NewAttribute(p11.CKA_LABEL, label),
	}
	objs, err := findObjects(context, session, template)
	if err != nil {
		return noKey, err
	}
	if len(objs) == 0 {
		return noKey, errors.New("key not found")
	}
	return objs[0], nil
}

func findObjects(context PKCS11Ctx, session p11.SessionHandle, template []*p11.Attribute) ([]p11.ObjectHandle, error) {
	const maxObjects = 2
	if err := context.FindObjectsInit(session, template); err != nil {
		return nil, err
	}
	objs, _, err := context.FindObjects(session, maxObjects)
	if err != nil {
		return nil, err
	}
	if err = context.FindObjectsFinal(session); err != nil {
		return nil, err
	}
	return objs, nil
}

// Config is the config struct used in pkcs11
type Config struct {
	// Keys are a map of key identifier and info
	Keys map[crypki.SignType]KeyInfo
	// ModulePath is the path of pkcs11 module
	ModulePath string
}

// KeyInfo contains the info of specific key
type KeyInfo struct {
	// SlotNumber indicates slot number on the HSM
	SlotNumber uint
	// UserPinPath indicates the filepath which contains the pin to login
	// to the specified slot.
	UserPinPath string
	// KeyLabel indicates the label of the key on the slot
	KeyLabel string
	// SignersPerPool is the number of signers we assign on a specific key
	SignersPerPool int
	// KeyType specifies the type of key, such as RSA or ECDSA.
	KeyType crypki.PublicKeyAlgorithm
}
