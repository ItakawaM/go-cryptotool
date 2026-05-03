package ciphers

import (
	"fmt"

	"github.com/ItakawaM/arcipher/ciphers/mathutils"
)

/*
CaesarCipher is a substitution cipher that shifts letters by a fixed key.

It uses precomputed substitution and reverse tables for efficient encryption/decryption.

Example:

	Key:        3
	Plaintext:  Hello
	-----------------
	+H e l l o
	 3 3 3 3 3
	 K h o o r
	-----------------
	Ciphertext: Khoor
*/
type CaesarCipher struct {
	key               byte
	substitutionTable [256]byte
	reverseTable      [256]byte
}

/*
CarsarKey represents a key for Caesar cipher.

It consists of a byte shift.
*/
type CaesarKey struct {
	Key int `json:"key"`
}

/*
Key returns the underlying key.
*/
func (cc *CaesarCipher) Key() CaesarKey {
	return CaesarKey{
		Key: int(cc.key),
	}
}

/*
NewCaesarCipher creates a new Caesar cipher with the given key.

The key is the number of positions to shift letters (keys are reduced modulo 26).
It supports negative keys.
*/
func NewCaesarCipher(key *CaesarKey) *CaesarCipher {
	parsedKey := byte(mathutils.Mod26(key.Key))

	var substitutionTable [256]byte
	var reverseTable [256]byte

	for i := range 256 {
		char := byte(i)
		switch {
		case char >= 'a' && char <= 'z':
			newChar := 'a' + (char-'a'+parsedKey)%26
			substitutionTable[char] = newChar
			reverseTable[newChar] = char

		case char >= 'A' && char <= 'Z':
			newChar := 'A' + (char-'A'+parsedKey)%26
			substitutionTable[char] = newChar
			reverseTable[newChar] = char

		default:
			substitutionTable[char] = char
			reverseTable[char] = char
		}
	}

	return &CaesarCipher{
		key:               parsedKey,
		substitutionTable: substitutionTable,
		reverseTable:      reverseTable,
	}
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Caesar cipher supports in-place operations.
*/
func (cc *CaesarCipher) IsInPlace() bool {
	return true
}

/*
EncryptBlock encrypts src using the Caesar cipher and writes the result to dst.

src and dst can alias, because Caesar cipher performs operations in-place.

src and dst must be the same length.
*/
func (cc *CaesarCipher) EncryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	if cc.key == 0 {
		copy(dst, src)
		return nil
	}

	for index, char := range src {
		dst[index] = cc.substitutionTable[char]
	}

	return nil
}

/*
DecryptBlock decrypts src using the Caesar cipher and writes the result to dst.

src and dst can alias, because Caesar cipher performs operations in-place.

src and dst must be the same length.
*/
func (cc *CaesarCipher) DecryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	if cc.key == 0 {
		copy(dst, src)
		return nil
	}

	for index, char := range src {
		dst[index] = cc.reverseTable[char]
	}

	return nil
}
