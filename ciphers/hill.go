package ciphers

import (
	"fmt"

	"github.com/ItakawaM/arcipher/ciphers/mathutils"
)

// inv2mod13 is the modular inverse of 2 modulo 13 (2 * 7 is congruent to 1 mod 13).
const inv2mod13 = 7

/*
HillCipher is a Hill cipher implementation that uses matrix multiplication over Z26.

The cipher encrypts blocks of a-zA-Z characters by treating each block as a vector and multiplying
it by a NxN key matrix. Non-alphabetic characters are preserved and not transformed.

It does not preserve cases.

Leftover a-zA-Z characters that can't create a Nx1 vector are left unencrypted.
*/
type HillCipher struct {
	key        *mathutils.Matrix[int]
	inverseKey *mathutils.Matrix[int]
}

/*
Key returns the cipher's Key Matrix.
*/
func (hc *HillCipher) Key() mathutils.Matrix[int] {
	return *hc.key
}

/*
InverseKey returns the inverse matrix to cipher's Key Matrix, such so:

Key x Inverse = Identity Matrix
*/
func (hc *HillCipher) InverseKey() mathutils.Matrix[int] {
	return *hc.inverseKey
}

func crtCombine(numberA int, numberB int) int {
	/*
		Solve
		x is congruent to a mod 2
		x is congruent to b mod 13
	*/
	temp := mathutils.Mod26((numberB - numberA))
	temp, _ = mathutils.Mod(temp*inv2mod13, 13) // modulo is 13, never fails

	return (numberA + 2*temp)
}

/*
NewHillCipher creates a new Hill cipher with the given key matrix.

The key matrix must be square and invertible modulo 26. The function computes the inverse
key matrix using the Chinese Remainder Theorem, combining inverses modulo 2 and modulo 13
to produce the inverse modulo 26.

Returns an error if the key matrix is not square or not invertible.
*/
func NewHillCipher(keyMatrix [][]int) (*HillCipher, error) {
	/*
		Z26 is isomorphic to Z2 x Z13, so we can just compute
		key inverse modulo 2 and key inverse modulo 13 and then
		use the chinese remainder theorem to find key inverse modulo 26

		x = a + 2 * ((b - a) * 2^(-1) mod 13)
		https://en.wikipedia.org/wiki/Chinese_remainder_theorem
	*/
	key, err := mathutils.NewMatrixFromData(keyMatrix)
	if err != nil {
		return nil, err
	}

	keyInverse2, err := mathutils.MatrixInverseModuloPrime(key, 2)
	if err != nil {
		return nil, err
	}

	keyInverse13, err := mathutils.MatrixInverseModuloPrime(key, 13)
	if err != nil {
		return nil, err
	}

	// size is checked when creating a matrix, so it's always > 0
	size := key.Rows()
	inverseKey, _ := mathutils.NewMatrixZero[int](size, size)

	for i := range size {
		for j := range size {
			inverseKey.Data[i][j] = crtCombine(keyInverse2.Data[i][j], keyInverse13.Data[i][j])
		}
	}

	return &HillCipher{
		key:        key,
		inverseKey: inverseKey,
	}, nil
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Hill cipher supports in-place operations.
*/
func (hc *HillCipher) IsInPlace() bool {
	return true
}

func applyTransformation(dst []byte, src []byte, matrix *mathutils.Matrix[int]) error {
	size := matrix.Rows()
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch: got src=%d dst=%d", len(src), len(dst))
	}
	// Preserve non-ASCII a-zA-Z characters
	copy(dst, src)

	alphaPosition := 0
	vector := make([]int, size)
	indices := make([]int, size)
	for index, char := range src {
		if !IsASCIILetter(char) {
			continue
		}
		shift := int(ToASCIILetter(char))

		vector[alphaPosition] = shift
		indices[alphaPosition] = index
		alphaPosition += 1

		if alphaPosition == size {
			for i := range size {
				var value int
				for j := range size {
					value = mathutils.Mod26(value + matrix.Data[i][j]*vector[j])
				}
				dst[indices[i]] = byte(value) + 'a'
			}
			alphaPosition = 0
		}
	}

	return nil
}

/*
EncryptBlock encrypts src using the Hill cipher and writes the result to dst.

EncryptBlock multiplies the key matrix by blocks of ASCII letters.
Non-letter characters are passed through unchanged.

EncryptBlock does not preserve cases.

Leftover a-zA-Z characters that can't create a Nx1 vector are left unencrypted.

src and dst can alias, because Hill cipher performs operations in-place.

src and dst must be the same length.
*/
func (hc *HillCipher) EncryptBlock(dst []byte, src []byte) error {
	return applyTransformation(dst, src, hc.key)
}

/*
DecryptBlock decrypts src using the Hill cipher and writes the result to dst.

DecryptBlock multiplies the inverse key matrix by blocks of ASCII letters.
Non-letter characters are passed through unchanged.

DecryptBlock does not preserve cases.

Leftover a-zA-Z characters that can't create a Nx1 vector are left unencrypted.

src and dst can alias, because Hill cipher performs operations in-place.

src and dst must be the same length.
*/
func (hc *HillCipher) DecryptBlock(dst []byte, src []byte) error {
	return applyTransformation(dst, src, hc.inverseKey)
}
