package ciphers

import "fmt"

/*
RailFenceCipher is a transposition cipher that writes plaintext in a zigzag pattern
across a number of "rails" and then reads off row by row.

The key specifies the number of rails to use.

Example:

	key:        3
	Plaintext:  HelloWorld
	----------------------
	  l   o
	 e l w r d
	H   o   l
	----------------------
	Ciphertext: loelwrdHol
*/
type RailFenceCipher struct {
	key              int
	permutationTable []int
}

/*
RailFenceKey represents a key for a RailFence cipher.

It contains the height of the fence (Key)
and the length of the permutation block (PermutationLength).
*/
type RailFenceKey struct {
	Key               int `json:"keyy"`
	PermutationLength int `json:"permutation_length"`
}

/*
Key returns the underlying key and the length of the permutation block.
*/
func (rfc *RailFenceCipher) Key() RailFenceKey {
	return RailFenceKey{
		Key:               rfc.key,
		PermutationLength: len(rfc.permutationTable),
	}
}

/*
NewRailFenceCipher creates a new Rail Fence cipher with the given key.

The key consists of the height of the rails (must be >= 1) and the length of the block (must be >= 1).

If height is 1, permutationTable becomes nil. EncryptBlock() and DecryptBlock() handle the height == 1 case separately.

If height is >= permutationLength, permutationTable reverses the text.

Returns an error if the key is < 1 or length of the block is <= 0.
*/
func NewRailFenceCipher(key *RailFenceKey) (*RailFenceCipher, error) {
	height := key.Key
	permutationLength := key.PermutationLength

	if permutationLength <= 0 {
		return nil, fmt.Errorf("incorrect permutationLength provided: %d", permutationLength)
	}

	permutationTable := make([]int, permutationLength)
	if height < 1 {
		return nil, fmt.Errorf("incorrect key provided: %d", key)
	} else if height == 1 {
		// Encrypt() Decrypt() handle the height == 1 option
		return &RailFenceCipher{
			key:              height,
			permutationTable: nil,
		}, nil
		// Reverse order when height >= permutationLength
	} else if height >= permutationLength {
		for index := range permutationLength {
			permutationTable[index] = permutationLength - 1 - index
		}

		return &RailFenceCipher{
			key:              height,
			permutationTable: permutationTable,
		}, nil
	}

	cycle := 2 * (height - 1)
	rails := make([]int, permutationLength)
	for index := range permutationLength {
		cyclePosition := index % cycle
		if cyclePosition < height {
			rails[index] = cyclePosition
		} else {
			rails[index] = cycle - cyclePosition
		}
	}

	railOffset := make([]int, height)
	currentOffset := 0
	for rail := height - 1; rail >= 0; rail-- {
		railOffset[rail] = currentOffset

		for index := rail; index < permutationLength; index += cycle {
			currentOffset += 1

			if rail != 0 && rail != height-1 {
				if secondIndex := index + cycle - 2*rail; secondIndex < permutationLength {
					currentOffset += 1
				}
			}
		}
	}

	for index := range permutationLength {
		permutationTable[index] = railOffset[rails[index]]
		railOffset[rails[index]]++
	}

	return &RailFenceCipher{
		key:              height,
		permutationTable: permutationTable,
	}, nil
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Rail Fence cipher does not support in-place operations since bytes are written
to non-sequential positions, requiring a separate destination buffer.
*/
func (rfc *RailFenceCipher) IsInPlace() bool {
	return false
}

/*
EncryptBlock encrypts src using the Rail Fence cipher and writes the result to dst.

src and dst cannot alias.

src and dst must be the same length and must match the permutationLength used when creating the cipher.
*/
func (rfc *RailFenceCipher) EncryptBlock(dst []byte, src []byte) error {
	if len(src) != len(dst) {
		return fmt.Errorf("block size mismatch: src = %d dst = %d", len(src), len(dst))
	}

	if rfc.key == 1 {
		copy(dst, src)
		return nil
	}

	blockSize := len(rfc.permutationTable)
	if len(src) != blockSize {
		return fmt.Errorf("block size mismatch: expected %d, got %d", blockSize, len(src))
	}

	for index := range src {
		dst[rfc.permutationTable[index]] = src[index]
	}

	return nil
}

/*
DecryptBlock decrypts src using the Rail Fence cipher and writes the result to dst.

src and dst cannot alias.

src and dst must be the same length and must match the permutationLength used when creating the cipher.
*/
func (rfc *RailFenceCipher) DecryptBlock(dst []byte, src []byte) error {
	if len(src) != len(dst) {
		return fmt.Errorf("block size mismatch: src = %d dst = %d", len(src), len(dst))
	}

	if rfc.key == 1 {
		copy(dst, src)
		return nil
	}

	blockSize := len(rfc.permutationTable)
	if len(src) != blockSize {
		return fmt.Errorf("block size mismatch: expected %d, got %d", blockSize, len(src))
	}
	for index := range src {
		dst[index] = src[rfc.permutationTable[index]]
	}

	return nil
}
