package ciphers

import "fmt"

/*
VigenereCipher is a polyalphabetic substitution cipher that uses a keyword
to encrypt messages by shifting each letter by a different amount based on
the corresponding letter in the key.

Example:
	Key:        Cat
	Plaintext:  HelloWorld
	---------------------
	+H e l l o W o r l d
	 C a t C a t C a t C
	 J e e n o P q r e f
	---------------------
	Ciphertext: JeenoPqref
*/
type VigenereCipher struct {
	key []byte
}

/*
VigenereKey represents a Vigenere/Vigenere Auto-Key cipher key.

It consists of a word/key/phrase/sequence of ASCII a-zA-Z letters.
*/
type VigenereKey struct {
	Key []byte `json:"key"`
}

/*
Key returns the underlying key.
*/
func (vc *VigenereCipher) Key() VigenereKey {
	return VigenereKey{
		Key: vc.key,
	}
}

/*
NormalizeVigenereKey normalizes a Vigenere key by converting all letters to lowercase
and returning only the shift values (a=0, b=1, ..., z=25).

Returns an error if the key is empty or contains non-letter characters.
*/
func NormalizeVigenereKey(key *VigenereKey) ([]byte, error) {
	if len(key.Key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	normalizedKey := make([]byte, len(key.Key))
	for index, char := range key.Key {
		if !IsASCIILetter(char) {
			return nil, fmt.Errorf("key can only consist of ASCII letters")
		}
		normalizedKey[index] = ToASCIILetter(char)
	}

	return normalizedKey, nil
}

/*
NewVigenereCipher creates a new Vigenere cipher with the given key.

The key must be a non-empty string of ASCII letters.

Returns an error if the key is invalid.
*/
func NewVigenereCipher(key *VigenereKey) (*VigenereCipher, error) {
	normalizedKey, err := NormalizeVigenereKey(key)
	if err != nil {
		return nil, err
	}

	return &VigenereCipher{
		key: normalizedKey,
	}, nil
}

/*
NewVigenereCipherNormalized creates a new Vigenere cipher with an already normalized key.
*/
func NewVigenereCipherNormalized(key []byte) *VigenereCipher {
	return &VigenereCipher{
		key: key,
	}
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Vigenere cipher supports in-place operations.
*/
func (vc *VigenereCipher) IsInPlace() bool {
	return true
}

/*
EncryptBlock encrypts src using the Vigenere cipher and writes the result to dst.

The key cycles over letter characters only; non-letter characters are passed through unchanged.

src and dst can alias, because Vigenere cipher performs operations in-place.

src and dst must be the same length.
*/
func (vc *VigenereCipher) EncryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	keyIndex := 0
	keyCycle := len(vc.key)
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

		dst[index] = shiftChar(char, base, vc.key[keyIndex])
		keyIndex++
		if keyIndex == keyCycle {
			keyIndex = 0
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
func (vc *VigenereCipher) DecryptBlock(dst []byte, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch src=%d dst=%d", len(src), len(dst))
	}

	keyIndex := 0
	keyCycle := len(vc.key)
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

		dst[index] = unshiftChar(char, base, vc.key[keyIndex])
		keyIndex++
		if keyIndex == keyCycle {
			keyIndex = 0
		}
	}

	return nil
}
