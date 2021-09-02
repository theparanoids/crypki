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
