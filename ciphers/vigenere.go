package ciphers

import "fmt"

type VigenereCipher struct {
	Key []byte
}

func isASCIILetter(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}

func getShift(k byte) byte {
	if k >= 'a' && k <= 'z' {
		return k - 'a'
	}

	return k - 'A'
}

func NormalizeVigenereKey(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	normalizedKey := make([]byte, len(key))
	for index, char := range key {
		if !isASCIILetter(char) {
			return nil, fmt.Errorf("key can only consist of ASCII letters")
		}
		normalizedKey[index] = getShift(char)
	}

	return normalizedKey, nil
}

func NewVigenereCipher(key []byte) (*VigenereCipher, error) {
	normalizedKey, err := NormalizeVigenereKey(key)
	if err != nil {
		return nil, err
	}

	return &VigenereCipher{
		Key: normalizedKey,
	}, nil
}

func NewVigenereCipherNormalized(normalizedKey []byte) *VigenereCipher {
	return &VigenereCipher{Key: normalizedKey}
}

func (vCipher *VigenereCipher) IsInPlace() bool {
	return true
}

func (vCipher *VigenereCipher) EncryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	keyIndex := 0
	keyCycle := len(vCipher.Key)
	for index, char := range src {
		if char >= 'a' && char <= 'z' {
			dst[index] = (char-'a'+(vCipher.Key[keyIndex%keyCycle]))%26 + 'a'
			keyIndex += 1
		} else if char >= 'A' && char <= 'Z' {
			dst[index] = (char-'A'+(vCipher.Key[keyIndex%keyCycle]))%26 + 'A'
			keyIndex += 1
		} else {
			dst[index] = char
		}
	}

	return nil
}

func (vCipher *VigenereCipher) DecryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	keyIndex := 0
	keyCycle := len(vCipher.Key)
	for index, char := range src {
		if char >= 'a' && char <= 'z' {
			dst[index] = (char-'a'-(vCipher.Key[keyIndex%keyCycle])+26)%26 + 'a'
			keyIndex += 1
		} else if char >= 'A' && char <= 'Z' {
			dst[index] = (char-'A'-(vCipher.Key[keyIndex%keyCycle])+26)%26 + 'A'
			keyIndex += 1
		} else {
			dst[index] = char
		}
	}

	return nil
}
