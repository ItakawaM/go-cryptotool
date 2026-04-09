// Package ciphers provides implementations of various classical and modern encryption ciphers.
package ciphers

import "fmt"

/*
RailFenceCipher is a transposition cipher that writes plaintext in a zigzag pattern
across a number of "rails" and then reads off row by row.

The key specifies the number of rails to use.
*/
type RailFenceCipher struct {
	Key              int
	PermutationTable []int
}

/*
NewRailFenceCipher creates a new Rail Fence cipher with the given key and block size.

The key is the number of rails (must be >= 1).

If key is 0, PermutationTable becomes nil. EncryptBlock() and DecryptBlock() handle the key == 1 case separately.

The block size is the size of plaintext blocks (must be > 0).

Returns an error if the key is < 1 or block size is <= 0.
*/
func NewRailFenceCipher(key int, blockSize int) (*RailFenceCipher, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("incorrect blockSize provided: %d", blockSize)
	}

	permutationTable := make([]int, blockSize)

	if key < 1 {
		return nil, fmt.Errorf("incorrect key provided: %d", key)
		// Reverse order when Key >= BlockSize
	} else if key == 1 {
		// Encrypt() Decrypt() handle the key == 1 option
		return &RailFenceCipher{
			Key:              key,
			PermutationTable: nil,
		}, nil
	} else if key >= blockSize {
		for index := range blockSize {
			permutationTable[index] = blockSize - 1 - index
		}

		return &RailFenceCipher{
			Key:              key,
			PermutationTable: permutationTable,
		}, nil
	}

	cycle := 2 * (key - 1)

	rails := make([]int, blockSize)
	for index := range blockSize {
		cyclePosition := index % cycle
		if cyclePosition < key {
			rails[index] = cyclePosition
		} else {
			rails[index] = cycle - cyclePosition
		}
	}

	railOffset := make([]int, key)
	currentOffset := 0
	for rail := key - 1; rail >= 0; rail-- {
		railOffset[rail] = currentOffset

		for index := rail; index < blockSize; index += cycle {
			currentOffset += 1

			if rail != 0 && rail != key-1 {
				if secondIndex := index + cycle - 2*rail; secondIndex < blockSize {
					currentOffset += 1
				}
			}
		}
	}

	for index := range blockSize {
		permutationTable[index] = railOffset[rails[index]]
		railOffset[rails[index]]++
	}

	return &RailFenceCipher{
		Key:              key,
		PermutationTable: permutationTable,
	}, nil
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Rail Fence cipher does not support in-place operations since bytes are written
to non-sequential positions, requiring a separate destination buffer.
*/
func (rfCipher *RailFenceCipher) IsInPlace() bool {
	return false
}

/*
EncryptBlock encrypts src using the Rail Fence cipher and writes the result to dst.

src and dst cannot alias.

src and dst must be the same length and must match the blockSize used when creating the cipher.
*/
func (rfCipher *RailFenceCipher) EncryptBlock(dst []byte, src []byte) error {
	blockSize := len(rfCipher.PermutationTable)
	if (len(src) != blockSize || len(dst) != blockSize) && rfCipher.PermutationTable != nil {
		return fmt.Errorf("block size mismatch: expected %d, got src=%d dst=%d", blockSize, len(src), len(dst))
	}

	if rfCipher.Key == 1 {
		copy(dst, src)
		return nil
	}

	for index := range src {
		dst[rfCipher.PermutationTable[index]] = src[index]
	}

	return nil
}

/*
DecryptBlock decrypts src using the Rail Fence cipher and writes the result to dst.

src and dst cannot alias.

src and dst must be the same length and must match the blockSize used when creating the cipher.
*/
func (rfCipher *RailFenceCipher) DecryptBlock(dst []byte, src []byte) error {
	blockSize := len(rfCipher.PermutationTable)
	if (len(src) != blockSize || len(dst) != blockSize) && rfCipher.PermutationTable != nil {
		return fmt.Errorf("block size mismatch: expected %d, got src=%d dst=%d", blockSize, len(src), len(dst))
	}

	if rfCipher.Key == 1 {
		copy(dst, src)
		return nil
	}

	for index := range src {
		dst[index] = src[rfCipher.PermutationTable[index]]
	}

	return nil
}
