// Package ciphers provides implementations of various classical and modern encryption ciphers.
package ciphers

import (
	"fmt"
)

/*
CaesarCipher is a substitution cipher that shifts letters by a fixed key.

It uses precomputed substitution and reverse tables for efficient encryption/decryption.
*/
type CaesarCipher struct {
	Key               byte
	SubstitutionTable [256]byte
	ReverseTable      [256]byte
}

/*
NewCaesarCipher creates a new Caesar cipher with the given key.

The key is the number of positions to shift letters (keys are reduced modulo 26).

Returns an error if the key is negative.
*/
func NewCaesarCipher(key int) (*CaesarCipher, error) {
	if key < 0 {
		return nil, fmt.Errorf("incorrect key provided: %d", key)
	}
	parsedKey := byte(key % 26)

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
		Key:               parsedKey,
		SubstitutionTable: substitutionTable,
		ReverseTable:      reverseTable,
	}, nil
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

	if cc.Key == 0 {
		copy(dst, src)
		return nil
	}

	for index, char := range src {
		dst[index] = cc.SubstitutionTable[char]
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

	if cc.Key == 0 {
		copy(dst, src)
		return nil
	}

	for index, char := range src {
		dst[index] = cc.ReverseTable[char]
	}

	return nil
}
