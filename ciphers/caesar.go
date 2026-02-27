package ciphers

import "fmt"

type CaesarCipher struct {
	Key               byte
	InPlace           bool
	SubstitutionTable [256]byte
	ReverseTable      [256]byte
}

func NewCaesarCipher(key byte) (*CaesarCipher, error) {
	if key < 1 {
		return nil, fmt.Errorf("incorrect key provided: %d", key)
	}

	var substitutionTable [256]byte
	var reverseTable [256]byte

	for char := range byte(255) {
		if char >= 'a' && char <= 'z' {
			newChar := 'a' + (char-'a'+key)%26
			substitutionTable[char] = newChar
			reverseTable[newChar] = char
		} else if char >= 'A' && char <= 'Z' {
			newChar := 'A' + (char-'A'+key)%26
			substitutionTable[char] = newChar
			reverseTable[newChar] = char
		} else {
			substitutionTable[char] = char
			reverseTable[char] = char
		}
	}

	return &CaesarCipher{
		Key:               key % 26,
		InPlace:           true,
		SubstitutionTable: substitutionTable,
		ReverseTable:      reverseTable,
	}, nil
}

func (cc *CaesarCipher) IsInPlace() bool {
	return cc.InPlace
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
