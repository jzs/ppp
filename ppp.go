/*
Copyright (c) 2012 Jens Zeilund (http://sketchground.dk)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package ppp

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

type Ppp struct {
	sequenceKey    []byte
	alphabet       string
	passcodeLength int
	codesPerCard   int
}

// NewPpp creates a new perfect paper passwords struct based on the given
// sequence key, alphabet and passcodeLength.
func NewPpp(sequenceKey []byte, alphabet string, passcodeLength, codesPerCard int) *Ppp {
	return &Ppp{sequenceKey, alphabet, passcodeLength, codesPerCard}
}

// ConvertHexToKey converts a hex string into a byte array.
func ConvertHexToKey(sequenceKey string) ([]byte, error) {
	s, err := hex.DecodeString(sequenceKey)
	if err != nil {
		return nil, err
	}
	key := []byte(s)
	return key, nil
}

// GenerateSequenceKeyFromString procudes a valid sequenceKey(sha hash) based 
// on a passPhrase.
func GenerateSequenceKeyFromString(passPhrase string) []byte {
	hash := sha256.New()
	hash.Write([]byte(passPhrase))
	return hash.Sum(nil)
}

// GetPasscode returns passcode num.
func (ppp *Ppp) GetPasscode(num *big.Int) string {
	passcodes := ppp.retrievePasscodes(num, 1, ppp.sequenceKey, ppp.alphabet, ppp.passcodeLength)
	return passcodes[0]
}

// GetPasscodes Retrieves a range of passcodes from firstPasscode.
func (ppp *Ppp) GetPasscodes(firstPasscode *big.Int, count int) []string {
	return ppp.retrievePasscodes(firstPasscode, count, ppp.sequenceKey, ppp.alphabet, ppp.passcodeLength)
}

func (ppp *Ppp) retrievePasscodes(firstPasscodeNumber *big.Int, passcodeCount int, sequenceKey []byte, sourceAlphabet string, passcodeLength int) []string {
	alphabetLength := len(sourceAlphabet)
	alphabet := []byte(sourceAlphabet)

	var passcodeList []string

	// Bubblesort the alphabet...
	for i := 0; i < alphabetLength; i++ {
		for j := 0; j < alphabetLength; j++ {
			if alphabet[i] < alphabet[j] {
				c := alphabet[j]
				alphabet[j] = alphabet[i]
				alphabet[i] = c
			}
		}
	}

	// Copy the key
	key := sequenceKey

	plain := firstPasscodeNumber    // What to encrypt essencially based on the key.
	passcodeCount *= passcodeLength // How many characters should we compute.

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	cipher := make([]byte, block.BlockSize()) // The encrypted cipher.
	bCipher := big.NewInt(0)

	for passcodeCount > 0 { // For each passcode that we need to generate.
		plainBytes := make([]byte, 16)
		for i, _ := range plainBytes {
			if i < len(plain.Bytes()) {
				plainBytes[i] = plain.Bytes()[i]
			} else {
				break
			}
		}
		block.Encrypt(cipher, plainBytes)

		// Swap bytes
		ncip := make([]byte, len(cipher))
		adjust := len(cipher) - 1
		for i := 0; i < len(cipher); i++ {
			ncip[i] = cipher[adjust-i]
		}
		cipher = ncip

		plain = plain.Add(big.NewInt(1), plain) // Prepare for next character.
		bCipher = bCipher.SetBytes(cipher)      // Bye cipher

		index := big.NewInt(0)

		passcode := make([]byte, passcodeLength)
		for i := 0; i < passcodeLength && passcodeCount > 0; i++ {
			bCipher, index = bCipher.DivMod(bCipher, big.NewInt(int64(alphabetLength)), big.NewInt(1))
			passcode[i] = alphabet[index.Int64()]
			passcodeCount--
		}
		passcodeList = append(passcodeList, string(passcode))
	}
	return passcodeList
}
