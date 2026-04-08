// Package ciphers provides implementations of various classical and modern encryption ciphers.
package ciphers

import "fmt"

/*
VigenereCipher is a polyalphabetic substitution cipher that uses a keyword
to encrypt messages by shifting each letter by a different amount based on
the corresponding letter in the key.
*/
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

/*
NormalizeVigenereKey normalizes a Vigenere key by converting all letters to lowercase
and returning only the shift values (a=0, b=1, ..., z=25).

Returns an error if the key is empty or contains non-letter characters.
*/
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

/*
NewVigenereCipher creates a new Vigenere cipher with the given key.

The key must be a non-empty string of ASCII letters.

Returns an error if the key is invalid.
*/
func NewVigenereCipher(key []byte) (*VigenereCipher, error) {
	normalizedKey, err := NormalizeVigenereKey(key)
	if err != nil {
		return nil, err
	}

	return &VigenereCipher{
		Key: normalizedKey,
	}, nil
}

/*
NewVigenereCipherNormalized creates a new Vigenere cipher with an already normalized key.
*/
func NewVigenereCipherNormalized(normalizedKey []byte) *VigenereCipher {
	return &VigenereCipher{Key: normalizedKey}
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Vigenere cipher supports in-place operations.
*/
func (vCipher *VigenereCipher) IsInPlace() bool {
	return true
}

/*
EncryptBlock encrypts src using the Vigenere cipher and writes the result to dst.

The key cycles over letter characters only; non-letter characters are passed through unchanged.

src and dst can alias, because Vigenere cipher performs operations in-place.

src and dst must be the same length.
*/
func (vCipher *VigenereCipher) EncryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	keyIndex := 0
	keyCycle := len(vCipher.Key)
	for index, char := range src {
		switch {
		case char >= 'a' && char <= 'z':
			dst[index] = (char-'a'+(vCipher.Key[keyIndex%keyCycle]))%26 + 'a'
			keyIndex += 1

		case char >= 'A' && char <= 'Z':
			dst[index] = (char-'A'+(vCipher.Key[keyIndex%keyCycle]))%26 + 'A'
			keyIndex += 1

		default:
			dst[index] = char
		}
	}

	return nil
}

/*
DecryptBlock decrypts src using the Vigenere cipher and writes the result to dst.

The key cycles over letter characters only; non-letter characters are passed through unchanged.

src and dst can alias, because Vigenere cipher performs operations in-place.

src and dst must be the same length.
*/
func (vCipher *VigenereCipher) DecryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	keyIndex := 0
	keyCycle := len(vCipher.Key)
	for index, char := range src {
		switch {
		case char >= 'a' && char <= 'z':
			dst[index] = (char-'a'-(vCipher.Key[keyIndex%keyCycle])+26)%26 + 'a'
			keyIndex += 1

		case char >= 'A' && char <= 'Z':
			dst[index] = (char-'A'-(vCipher.Key[keyIndex%keyCycle])+26)%26 + 'A'
			keyIndex += 1

		default:
			dst[index] = char
		}
	}

	return nil
}
