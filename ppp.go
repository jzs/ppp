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

func NewPpp(sequenceKey []byte, alphabet string, passcodeLength, codesPerCard int) *Ppp {
	return &Ppp{sequenceKey, alphabet, passcodeLength, codesPerCard}
}

func ConvertHexToKey(sequenceKey string) ([]byte, error) {
	s, err := hex.DecodeString(sequenceKey)
	if err != nil {
		return nil, err
	}
	key := []byte(s)
	return key, nil
}

func GenerateSequenceKeyFromString(passPhrase string) []byte {
	hash := sha256.New()
	hash.Write([]byte(passPhrase))
	return hash.Sum(nil)
}

func (ppp *Ppp) GetPasscode(num *big.Int) string {
	passcodes := ppp.retrievePasscodes(num, 1, ppp.sequenceKey, ppp.alphabet, ppp.passcodeLength)
	return passcodes[0]
}

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
