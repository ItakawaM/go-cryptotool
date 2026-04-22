// Package ciphers provides implementations of various classical and modern encryption ciphers.
package ciphers

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

/*
CipherMode represents the mode of operation for a cipher, either encryption or decryption.
*/
type CipherMode int8

const (
	// Encrypt indicates encryption mode.
	Encrypt CipherMode = iota
	// Decrypt indicates decryption mode.
	Decrypt
)

/*
String returns the string representation of the CipherMode.
*/
func (mode CipherMode) String() string {
	if mode == Encrypt {
		return "encrypt"
	}
	return "decrypt"
}

/*
IsASCIILetter checks whether the provided char is an ASCII a-zA-Z letter.
*/
func IsASCIILetter(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}

/*
ToASCIILetter converts an ASCII letter to its position in the alphabet (0-25).

For lowercase letters (a-z), it returns 0-25.
For uppercase letters (A-Z), it returns 0-25.
For non-letter characters, it returns the character unchanged.

Should be used together with IsASCIILetter.
*/
func ToASCIILetter(char byte) byte {
	switch {
	case char >= 'a' && char <= 'z':
		return char - 'a'

	case char >= 'A' && char <= 'Z':
		return char - 'A'
	}

	return char
}

/*
RandSequenceIntMaxN generates a sequence of random integers in the range [0, n).

It returns a channel that produces count random integers, each in the range [0, n).
The function uses crypto/rand for cryptographically secure random numbers.

Returns an error if n <= 0 or count <= 0.
*/
func RandSequenceIntMaxN(n int, count int) (<-chan int, error) {
	if n <= 0 {
		return nil, fmt.Errorf("n has to be positive, got = %d", n)
	}
	if count <= 0 {
		return nil, fmt.Errorf("count has to be positive, got = %d", count)
	}

	limit := big.NewInt(int64(n))
	result := make(chan int, count)
	for range count {
		value, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		result <- int(value.Int64())
	}

	close(result)
	return result, nil
}

/*
BlockCipher is the interface that all block ciphers must implement.

It provides methods for encryption and decryption of fixed-size blocks.
*/
type BlockCipher interface {
	/*
		IsInPlace returns whether the cipher can perform encryption/decryption in-place.

		In-place operations allow src and dst slices to alias.
	*/
	IsInPlace() bool
	/*
		EncryptBlock encrypts src and writes the result to dst.

		If implementation allows for in-place operations, dst and src can alias.

		src and dst must be the same length; the expected length is
		implementation-defined — consult the concrete type for details.
	*/
	EncryptBlock(dst []byte, src []byte) error
	/*
		DecryptBlock decrypts src and writes the result to dst.

		If implementation allows for in-place operations, dst and src can alias.

		src and dst must be the same length; the expected length is
		implementation-defined — consult the concrete type for details.
	*/
	DecryptBlock(dst []byte, src []byte) error
}
