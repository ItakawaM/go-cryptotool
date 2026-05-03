package ciphers

import (
	"fmt"

	"github.com/ItakawaM/arcipher/ciphers/mathutils"
)

// inv2mod13 is the modular inverse of 2 modulo 13 (2 * 7 is congruent to 1 mod 13).
const inv2mod13 = 7

/*
AffineCipher is a k-rank Affine cipher implementation over Z26.

The cipher encrypts blocks of a-zA-Z characters using the affine transformation:
c = (M * p + b) mod 26

Where M is an NxN invertible matrix key and b is an N-dimensional key vector.
Non-alphabetic characters are preserved and not transformed.

Leftover a-zA-Z characters that can't create a Nx1 vector are left unencrypted.
*/
type AffineCipher struct {
	matrixKey        *mathutils.Matrix[int]
	inverseMatrixKey *mathutils.Matrix[int]
	vectorKey        []int
}

/*
AffineKey represents the key for a Affine cipher.

It contains a square matrix and a key vector.
*/
type AffineKey struct {
	MatrixKey [][]int `json:"matrix"`
	VectorKey []int   `json:"vector"`
}

/*
Key returns the cipher's Key Matrix and the key vector.
*/
func (ac *AffineCipher) Key() AffineKey {
	return AffineKey{
		MatrixKey: ac.matrixKey.Data,
		VectorKey: ac.vectorKey,
	}
}

/*
InverseKey returns the inverse matrix to cipher's Key Matrix and the key vector, such so:

Key x Inverse = Identity Matrix
*/
func (ac *AffineCipher) InverseKey() AffineKey {
	return AffineKey{
		MatrixKey: ac.inverseMatrixKey.Data,
		VectorKey: ac.vectorKey,
	}
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

func calculateInverseKey(matrixKey *mathutils.Matrix[int]) (*mathutils.Matrix[int], error) {
	/*
		Z26 is isomorphic to Z2 x Z13, so we can just compute
		key inverse modulo 2 and key inverse modulo 13 and then
		use the chinese remainder theorem to find key inverse modulo 26

		x = a + 2 * ((b - a) * 2^(-1) mod 13)
		https://en.wikipedia.org/wiki/Chinese_remainder_theorem
	*/

	keyInverse2, err := mathutils.MatrixInverseModuloPrime(matrixKey, 2)
	if err != nil {
		return nil, err
	}

	keyInverse13, err := mathutils.MatrixInverseModuloPrime(matrixKey, 13)
	if err != nil {
		return nil, err
	}

	// size is checked when creating a matrix, so it's always > 0
	size := matrixKey.Rows()
	inverseKey, _ := mathutils.NewMatrixZero[int](size, size)

	for i := range size {
		for j := range size {
			inverseKey.Data[i][j] = crtCombine(keyInverse2.Data[i][j], keyInverse13.Data[i][j])
		}
	}

	return inverseKey, nil
}

/*
GenerateAffineKey generates a random invertible key for the Affine cipher.

The size parameter specifies the dimensions of the key matrix (NxN). The function generates
random matrices until it finds one that is invertible modulo 26 and returns it
together with a random key vector.

O(random) Time Complexity.

Returns an error if size <= 0.
*/
func GenerateAffineKey(size int) (*AffineKey, error) {
	if size <= 0 {
		return nil, fmt.Errorf("size must be > 0, got size = %d", size)
	}
	matrix, _ := mathutils.NewMatrixZero[int](size, size) // Can't fail, because rows and columns are checked earlier

	// Just try until it works
	// Most likely the most random-random matrix generator there is
	for {
		sequence, err := RandSequenceIntMaxN(26, size*size)
		if err != nil {
			return nil, err
		}

		for i := range size {
			for j := range size {
				matrix.Data[i][j] = <-sequence
			}
		}

		_, err = calculateInverseKey(matrix)
		if err != nil {
			continue
		}

		// After finding a viable matrix, just generate a vector key
		vectorSequence, err := RandSequenceIntMaxN(26, size)
		if err != nil {
			return nil, err
		}

		vectorKey := make([]int, size)
		for i := range size {
			vectorKey[i] = <-vectorSequence
		}

		return &AffineKey{
			MatrixKey: matrix.Data,
			VectorKey: vectorKey,
		}, nil
	}
}

/*
NewAffineCipher creates a new Affine cipher with the given key.

The key matrix must be square and invertible modulo 26. The function computes the inverse
key matrix using the Chinese Remainder Theorem, combining inverses modulo 2 and modulo 13
to produce the inverse modulo 26.

Returns an error if the key matrix is not square or not invertible
or if it doesn't match sizes with key vector.
*/
func NewAffineCipher(key *AffineKey) (*AffineCipher, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}

	if len(key.VectorKey) != len(key.MatrixKey) {
		return nil, fmt.Errorf("key vector must be of length matrix key, got vector = %d matrix = %d",
			len(key.VectorKey), len(key.MatrixKey))
	}

	matrixKey, err := mathutils.NewMatrixFromData(key.MatrixKey)
	if err != nil {
		return nil, err
	}

	inverseMatrixKey, err := calculateInverseKey(matrixKey)
	if err != nil {
		return nil, err
	}

	vectorKey := make([]int, len(key.VectorKey))
	for i := range vectorKey {
		vectorKey[i] = mathutils.Mod26(key.VectorKey[i])
	}

	return &AffineCipher{
		matrixKey:        matrixKey,
		inverseMatrixKey: inverseMatrixKey,
		vectorKey:        vectorKey,
	}, nil
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Affine cipher supports in-place operations.
*/
func (ac *AffineCipher) IsInPlace() bool {
	return true
}

func applyAffineTransformation(dst []byte, src []byte, size int, transform func(textVector []int, output []int)) error {
	if len(dst) != len(src) {
		return fmt.Errorf("block size mismatch: got src = %d dst = %d", len(src), len(dst))
	}
	// Preserve non-ASCII a-zA-Z characters
	copy(dst, src)

	alphaPosition := 0
	textVector := make([]int, size)
	outputVector := make([]int, size)

	indices := make([]int, size)
	upperFlags := make([]bool, size)
	for index, char := range src {
		if !IsASCIILetter(char) {
			continue
		}

		textVector[alphaPosition] = int(ToASCIILetter(char))
		upperFlags[alphaPosition] = IsUpperASCIILetter(char)
		indices[alphaPosition] = index

		alphaPosition += 1
		if alphaPosition == size {
			for i := range size {
				outputVector[i] = 0
			}

			transform(textVector, outputVector)
			for i := range size {
				if upperFlags[i] {
					dst[indices[i]] = byte(outputVector[i]) + 'A'
				} else {
					dst[indices[i]] = byte(outputVector[i]) + 'a'
				}
			}
			alphaPosition = 0
		}
	}

	return nil
}

/*
EncryptBlock encrypts src using the Affine cipher and writes the result to dst.

EncryptBlock multiplies the key matrix by blocks of ASCII letters and adds the key vector.
Non-letter characters are passed through unchanged.

Leftover a-zA-Z characters that can't create a Nx1 vector are left unencrypted.

src and dst can alias, because Affine cipher performs operations in-place.

src and dst must be the same length.
*/
func (ac *AffineCipher) EncryptBlock(dst []byte, src []byte) error {
	size := ac.matrixKey.Rows()
	return applyAffineTransformation(dst, src, size, func(textVector []int, output []int) {
		for i := range size {
			for j := range size {
				output[i] = mathutils.Mod26(output[i] + ac.matrixKey.Data[i][j]*textVector[j])
			}
			output[i] = mathutils.Mod26(output[i] + ac.vectorKey[i])
		}
	})
}

/*
DecryptBlock decrypts src using the Affine cipher and writes the result to dst.

DecryptBlock subtracts the key vector and then multiplies the inverse key matrix by blocks of ASCII letters.
Non-letter characters are passed through unchanged.

Leftover a-zA-Z characters that can't create a Nx1 vector are left unencrypted.

src and dst can alias, because Affine cipher performs operations in-place.

src and dst must be the same length.
*/
func (ac *AffineCipher) DecryptBlock(dst []byte, src []byte) error {
	size := ac.inverseMatrixKey.Rows()
	return applyAffineTransformation(dst, src, size, func(textVector []int, output []int) {
		for i := range size {
			textVector[i] = mathutils.Mod26(textVector[i] - ac.vectorKey[i])
		}

		for i := range size {
			for j := range size {
				output[i] = mathutils.Mod26(output[i] + ac.inverseMatrixKey.Data[i][j]*textVector[j])
			}
		}
	})
}
