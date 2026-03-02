package ciphers

import (
	"fmt"
)

type CaesarCipher struct {
	Key               byte
	SubstitutionTable [256]byte
	ReverseTable      [256]byte
}

func NewCaesarCipher(key int) (*CaesarCipher, error) {
	if key < 0 {
		return nil, fmt.Errorf("incorrect key provided: %d", key)
	}
	parsedKey := byte(key % 26)

	var substitutionTable [256]byte
	var reverseTable [256]byte

	for i := range 256 {
		char := byte(i)
		if char >= 'a' && char <= 'z' {
			newChar := 'a' + (char-'a'+parsedKey)%26
			substitutionTable[char] = newChar
			reverseTable[newChar] = char
		} else if char >= 'A' && char <= 'Z' {
			newChar := 'A' + (char-'A'+parsedKey)%26
			substitutionTable[char] = newChar
			reverseTable[newChar] = char
		} else {
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

func (cc *CaesarCipher) IsInPlace() bool {
	return true
}

func (cc *CaesarCipher) EncryptBlock(dst []byte, src []byte) error {
	if cc.Key == 0 {
		copy(dst, src)
		return nil
	}

	for index, char := range src {
		dst[index] = cc.SubstitutionTable[char]
	}

	return nil
}

func (cc *CaesarCipher) DecryptBlock(dst []byte, src []byte) error {
	if cc.Key == 0 {
		copy(dst, src)
		return nil
	}

	for index, char := range src {
		dst[index] = cc.ReverseTable[char]
	}

	return nil
}
