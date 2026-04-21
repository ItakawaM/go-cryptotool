// Package ciphers provides implementations of various classical and modern encryption ciphers.
package ciphers

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
