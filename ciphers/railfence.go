package ciphers

import "fmt"

type RailFenceCipher struct {
	Key              int
	PermutationTable []int
	InverseTable     []int
}

func NewRailFenceCipher(key int, blockSize int) (*RailFenceCipher, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("incorrect blockSize provided: %d", blockSize)
	}

	permutationTable := make([]int, blockSize)
	inverseTable := make([]int, blockSize)

	if key < 1 {
		return nil, fmt.Errorf("incorrect key provided: %d", key)
		// Reverse order when Key >= BlockSize
	} else if key == 1 {
		// Encrypt() Decrypt() handle the key == 1 option
		return &RailFenceCipher{
			Key:              key,
			PermutationTable: permutationTable,
			InverseTable:     inverseTable,
		}, nil
	} else if key >= blockSize {
		for index := range blockSize {
			permutationTable[index] = blockSize - 1 - index
			inverseTable[blockSize-1-index] = index
		}

		return &RailFenceCipher{
			Key:              key,
			PermutationTable: permutationTable,
			InverseTable:     inverseTable,
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
		inverseTable[railOffset[rails[index]]] = index
		railOffset[rails[index]]++
	}

	return &RailFenceCipher{
		Key:              key,
		PermutationTable: permutationTable,
		InverseTable:     inverseTable,
	}, nil
}

func (rfCipher *RailFenceCipher) IsInPlace() bool {
	return false
}

func (rfCipher *RailFenceCipher) EncryptBlock(dst []byte, src []byte) error {
	blockSize := len(rfCipher.PermutationTable)
	if len(src) != blockSize || len(dst) != blockSize {
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

func (rfCipher *RailFenceCipher) DecryptBlock(dst []byte, src []byte) error {
	blockSize := len(rfCipher.PermutationTable)
	if len(src) != blockSize || len(dst) != blockSize {
		return fmt.Errorf("block size mismatch: expected %d, got src=%d dst=%d", blockSize, len(src), len(dst))
	}

	if rfCipher.Key == 1 {
		copy(dst, src)
		return nil
	}

	for index := range src {
		dst[rfCipher.InverseTable[index]] = src[index]
	}

	return nil
}
