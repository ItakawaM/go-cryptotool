package ciphers

import "fmt"

type RailFenceCipher struct {
	Key              int
	PermutationTable []int
	InverseTable     []int
}

func NewRailFenceCipher(key int, blockSize int) (*RailFenceCipher, error) {
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
		// Blocks are always even numbers
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

func (rfCipher *RailFenceCipher) Visualize(message string) {
	if rfCipher.Key == 1 {
		fmt.Println(message)
		return
	}

	cycle := 2 * (rfCipher.Key - 1)
	blockSize := len(message)

	rails := make([]int, blockSize)
	for index := range blockSize {
		cyclePosition := index % cycle
		if cyclePosition < rfCipher.Key {
			rails[index] = cyclePosition
		} else {
			rails[index] = cycle - cyclePosition
		}
	}

	for rail := min(rfCipher.Key, blockSize) - 1; rail >= 0; rail-- {
		for index := range blockSize {
			if rails[index] == rail {
				fmt.Printf("%s ", string(message[index]))
			} else {
				fmt.Print(". ")
			}
		}
		fmt.Println("")
	}
}

func (rfCipher *RailFenceCipher) EncryptBlock(dst []byte, src []byte) error {
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
	if rfCipher.Key == 1 {
		copy(dst, src)
		return nil
	}

	for index := range src {
		dst[rfCipher.InverseTable[index]] = src[index]
	}

	return nil
}
