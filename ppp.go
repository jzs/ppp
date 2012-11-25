package main

import (
	"encoding/hex"
	"crypto/sha256"
	"fmt"
	"crypto/aes"
	"math/big"
)

type OneTwoEight struct {
	Big *big.Int
	low uint64
	high uint64
	Byte [16]byte
}

type SequenceKey struct {
	Byte []byte
}

func RetrievePasscodes(firstPasscodeNumber *big.Int, passcodeCount int, sequenceKey *SequenceKey, sourceAlphabet string, passcodeLength int) []string {

	alphabetLength := len(sourceAlphabet)
	alphabet := []byte(sourceAlphabet)

	passcodeList := make([]string, passcodeCount)

	// Bubblesort the alphabet...
	for i := 0; i < alphabetLength; i++ {
		for j := 0; j < alphabetLength; j++ {
			if alphabet[i] > alphabet[j] {
				c := alphabet[j]
				alphabet[j] = alphabet[i]
				alphabet[i] = c
			}
		}
	}
	fmt.Printf("Alphabet lenght: %d \n", len(alphabet))

	// Copy the key c-style
	key := make([]byte, len(sequenceKey.Byte))
	for i := 0; i < len(sequenceKey.Byte); i++ {
		key[i] = sequenceKey.Byte[i]
	}

	plain := firstPasscodeNumber // What to encrypt essencially based on the key.
	passcodeCount *= passcodeLength

	fmt.Printf("KEY: %x", key)
	block, err := aes.NewCipher(key); if err != nil { return nil }

	cipher := make([]byte, block.BlockSize()) // The encrypted cipher.
	bCipher := big.NewInt(0)

	for passcodeCount > 0 { // For each passcode that we need to generate.
		plainBytes := make([]byte, 16)
		for i, _ := range(plainBytes) {
			if i < len(plain.Bytes()) {
				plainBytes[i] = plain.Bytes()[i]
			} else {
				break
			}
		}
		fmt.Printf("PlainBytes: %x \n", plainBytes)
		block.Encrypt(cipher, plainBytes)

		plain = plain.Add(big.NewInt(1), plain)
		bCipher = bCipher.SetBytes(cipher)

		index := big.NewInt(0)

		fmt.Printf("Cipher: %x \n", cipher)
		fmt.Println("Looping: \n")
		passcode := make([]byte, passcodeLength)
		for i := 0; i < passcodeLength && passcodeCount > 0; i++ {
			fmt.Printf("Cipher Before: %x \n", bCipher.Bytes())
			bCipher, index = bCipher.DivMod(bCipher, big.NewInt(int64(alphabetLength)), big.NewInt(1))
			fmt.Printf("Alphabet Length: %d\n", len(alphabet))
			fmt.Println(index.Int64())
			passcode[i] = alphabet[index.Int64()]

			passcodeCount--
		}
		passcodeList = append(passcodeList, string(passcode))
	}
	return passcodeList
}

func GenerateRandomSequenceKey(key *SequenceKey) {
	key.Byte = []byte("deaad4ffca90ecc50b7b0d50f6fd16ae7e6aa4584d7f2349af8ac94d9e7de155")
}

func ConvertHexToKey(sequenceKey string, key *SequenceKey) bool {
	s, err := hex.DecodeString(sequenceKey); if err != nil { return false }
	key.Byte = []byte(s)
	return true
}

func GenerateSequenceKeyFromString(passPhrase string, key *SequenceKey) {
	hash := sha256.New()
	key.Byte = hash.Sum([]byte(passPhrase))
	return
}

func main() {
	passphrase := "bob"
	sequenceKey := "deaad4ffca90ecc50b7b0d50f6fd16ae7e6aa4584d7f2349af8ac94d9e7de155"
	offset := 1
	count := 1
	alphabet := "!#%+23456789=:?@ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	length := 4

	var key SequenceKey

	if(len(passphrase) == 0) {
		fmt.Println("Passphrase is empty. Generating random sequence key")
		GenerateRandomSequenceKey( &key)
	} else {
		if(len(sequenceKey) == 64 && ConvertHexToKey(sequenceKey, &key)) {
			fmt.Println("Using entered sequence key\n")
		} else {
			fmt.Println("Generating sequence key from passphrase\n")
			GenerateSequenceKeyFromString(passphrase, &key)
		}
	}
	fmt.Println("Sequence Key: ");

	fmt.Printf("%x\n", key.Byte)

	for i:= 0; i < len(key.Byte); i++ {
		fmt.Printf("0x%X,", key.Byte[i])
	}
	fmt.Printf("\n");

	//Computing passcodes-----------------------------

	firstPasscode := big.NewInt(int64(offset))

	fmt.Printf("Using alphabet: %s\n", alphabet)

	fmt.Printf("Passcode length: %d\n", length)

	pcl := RetrievePasscodes(firstPasscode, count, &key, alphabet, length)

	for _, s := range(pcl) {
		fmt.Printf("%s ", s)
	}
	fmt.Printf("\n")
}
