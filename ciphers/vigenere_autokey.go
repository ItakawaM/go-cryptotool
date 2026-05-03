package ciphers

import "fmt"

/*
VigenereAutoKeyCipher is a variant of the Vigenere cipher that uses the plaintext
itself (after the key) as the key for subsequent encryptions, providing
stronger security than the standard Vigenere cipher.

Example:

	key:        Cat
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
NewVigenereAutoKeyCipher creates a new Vigenere Auto-key cipher with the given key.

The key must be a non-empty string of ASCII letters.

Returns an error if the key is invalid.
*/
func NewVigenereAutoKeyCipher(key *VigenereKey) (*VigenereAutoKeyCipher, error) {
	normalizedKey, err := NormalizeVigenereKey(key)
	if err != nil {
		return nil, err
	}

	return &VigenereAutoKeyCipher{
		VigenereCipher{
			key: normalizedKey,
		},
	}, nil
}

/*
NewVigenereAutoKeyCipherNormalized creates a new Vigenere Auto-key cipher with an already normalized key.
*/
func NewVigenereAutoKeyCipherNormalized(key []byte) *VigenereAutoKeyCipher {
	return &VigenereAutoKeyCipher{
		VigenereCipher{
			key: key,
		}}
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Vigenere Auto-key cipher does not support in-place operations since
decryption reads from dst as key material before it is fully written.
*/
func (vCipher *VigenereAutoKeyCipher) IsInPlace() bool {
	return false
}

func shiftChar(char, base, shift byte) byte {
	return (char-base+shift)%26 + base
}

func unshiftChar(char, base, shift byte) byte {
	return (char-base-shift+26)%26 + base
}

/*
EncryptBlock encrypts src using the Vigenere Auto-key cipher and writes the result to dst.

The key cycles over letter characters only; non-letter characters are passed through unchanged.

src and dst cannot alias.

src and dst must be the same length.
*/
func (vCipher *VigenereAutoKeyCipher) EncryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	keyIndex := 0
	keyCycle := len(vCipher.key)
	letterIndex := 0
	for index, char := range src {
		base := byte(0)
		switch {
		case char >= 'a' && char <= 'z':
			base = 'a'
		case char >= 'A' && char <= 'Z':
			base = 'A'
		default:
			dst[index] = char
			continue
		}

		var shift byte
		if keyIndex < keyCycle {
			shift = vCipher.key[keyIndex]
		} else {
			for letterIndex < len(src) && !IsASCIILetter(src[letterIndex]) {
				letterIndex++
			}
			if letterIndex >= len(src) {
				return fmt.Errorf("ran out of plaintext key material at index %d", index)
			}
			shift = ToASCIILetter(src[letterIndex])
			letterIndex++
		}

		dst[index] = shiftChar(char, base, shift)
		keyIndex++
	}

	return nil
}

/*
DecryptBlock decrypts src using the Vigenere Auto-key cipher and writes the result to dst.

The key cycles over letter characters only; non-letter characters are passed through unchanged.

src and dst cannot alias.

src and dst must be the same length.
*/
func (vCipher *VigenereAutoKeyCipher) DecryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	keyIndex := 0
	keyCycle := len(vCipher.key)
	letterIndex := 0
	for index, char := range src {
		base := byte(0)
		switch {
		case char >= 'a' && char <= 'z':
			base = 'a'
		case char >= 'A' && char <= 'Z':
			base = 'A'
		default:
			dst[index] = char
			continue
		}

		var shift byte
		if keyIndex < keyCycle {
			shift = vCipher.key[keyIndex]
		} else {
			for letterIndex < len(dst) && !IsASCIILetter(dst[letterIndex]) {
				letterIndex++
			}
			if letterIndex >= len(dst) {
				return fmt.Errorf("ran out of plaintext key material at index %d", index)
			}
			shift = ToASCIILetter(dst[letterIndex])
			letterIndex++
		}

		dst[index] = unshiftChar(char, base, shift)
		keyIndex++
	}

	return nil
}
