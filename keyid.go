package crypki

// KeyIDProcessor is a interface containing all the possible operations on keyID.
type KeyIDProcessor interface {
	// Process will take in a key ID, add some more information, and then return the key ID back.
	Process(kid string) (string, error)
}

// KeyID contains all the fields in key ID.
type KeyID struct {
}

// Process can be used to add custom metadata like timestamp or crypki instance info to the keyID.
func (k *KeyID) Process(kid string) (string, error) {
	return kid, nil
}
