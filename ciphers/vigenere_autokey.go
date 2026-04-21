package ciphers

import "fmt"

/*
VigenereAutoKeyCipher is a variant of the Vigenere cipher that uses the plaintext
itself (after the key) as the key for subsequent encryptions, providing
stronger security than the standard Vigenere cipher.

Example:

	Key:        Cat
	Plaintext:  HelloWorld
	---------------------
	+H e l l o W o r l d
	 C a t H e l l o W o
	 J e e s s H z f h r
	---------------------
	Ciphertext: JeessHzfhr
*/
type VigenereAutoKeyCipher struct {
	VigenereCipher
}

/*
NewVigenereAutoKeyCipher creates a new Vigenere Auto-Key cipher with the given key.

The key must be a non-empty string of ASCII letters.

Returns an error if the key is invalid.
*/
func NewVigenereAutoKeyCipher(key []byte) (*VigenereAutoKeyCipher, error) {
	normalizedKey, err := NormalizeVigenereKey(key)
	if err != nil {
		return nil, err
	}

	return &VigenereAutoKeyCipher{VigenereCipher{Key: normalizedKey}}, nil
}

/*
NewVigenereAutoKeyCipherNormalized creates a new Vigenere Auto-Key cipher with an already normalized key.
*/
func NewVigenereAutoKeyCipherNormalized(normalizedKey []byte) *VigenereAutoKeyCipher {
	return &VigenereAutoKeyCipher{VigenereCipher{Key: normalizedKey}}
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Vigenere Auto-Key cipher does not support in-place operations since
decryption reads from dst as key material before it is fully written.
*/
func (vCipher *VigenereAutoKeyCipher) IsInPlace() bool {
	return false
}

/*
EncryptBlock encrypts src using the Vigenere Auto-Key cipher and writes the result to dst.

The key cycles over letter characters only; non-letter characters are passed through unchanged.

src and dst cannot alias.

src and dst must be the same length.
*/
func (vCipher *VigenereAutoKeyCipher) EncryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	keyIndex := 0
	keyCycle := len(vCipher.Key)
	letterIndex := 0
	for index, char := range src {
		switch {
		case char >= 'a' && char <= 'z':
			if keyIndex < keyCycle {
				dst[index] = (char-'a'+(vCipher.Key[keyIndex]))%26 + 'a'
			} else {
				for !IsASCIILetter(src[letterIndex]) {
					letterIndex += 1
				}
				dst[index] = (char-'a'+ToASCIILetter(src[letterIndex]))%26 + 'a'
				letterIndex += 1
			}
			keyIndex += 1

		case char >= 'A' && char <= 'Z':
			if keyIndex < keyCycle {
				dst[index] = (char-'A'+(vCipher.Key[keyIndex]))%26 + 'A'
			} else {
				for !IsASCIILetter(src[letterIndex]) {
					letterIndex += 1
				}
				dst[index] = (char-'A'+ToASCIILetter(src[letterIndex]))%26 + 'A'
				letterIndex += 1
			}
			keyIndex += 1

		default:
			dst[index] = char
		}
	}

	return nil
}

/*
DecryptBlock decrypts src using the Vigenere Auto-Key cipher and writes the result to dst.

The key cycles over letter characters only; non-letter characters are passed through unchanged.

src and dst cannot alias.

src and dst must be the same length.
*/
func (vCipher *VigenereAutoKeyCipher) DecryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	keyIndex := 0
	keyCycle := len(vCipher.Key)
	letterIndex := 0
	for index, char := range src {
		switch {
		case char >= 'a' && char <= 'z':
			if keyIndex < keyCycle {
				dst[index] = (char-'a'-(vCipher.Key[keyIndex])+26)%26 + 'a'
			} else {
				for !IsASCIILetter(src[letterIndex]) {
					letterIndex += 1
				}
				dst[index] = (char-'a'-ToASCIILetter(dst[letterIndex])+26)%26 + 'a'
				letterIndex += 1
			}
			keyIndex += 1

		case char >= 'A' && char <= 'Z':
			if keyIndex < keyCycle {
				dst[index] = (char-'A'-(vCipher.Key[keyIndex])+26)%26 + 'A'
			} else {
				for !IsASCIILetter(src[letterIndex]) {
					letterIndex += 1
				}
				dst[index] = (char-'A'-ToASCIILetter(dst[letterIndex])+26)%26 + 'A'
				letterIndex += 1
			}
			keyIndex += 1

		default:
			dst[index] = char
		}
	}

	return nil
}
