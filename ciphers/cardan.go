package ciphers

import (
	"fmt"
	"math/rand/v2"
	"slices"
)

type CardanCipher struct {
	PermutationTable []int
	InverseTable     []int
}

type point struct {
	row int
	col int
}

func pointToIndex(p point, gridSize int) int {
	return p.row*gridSize + p.col
}

func indexToPoint(index int, gridSize int) point {
	return point{index / gridSize, index % gridSize}
}

func rotate90(p point, gridSize int) point {
	return point{p.col, gridSize - 1 - p.row}
}

func getAllRotations(p point, gridSize int) [4]point {
	rotation90 := rotate90(p, gridSize)
	rotation180 := rotate90(rotation90, gridSize)
	rotation270 := rotate90(rotation180, gridSize)

	return [4]point{p, rotation90, rotation180, rotation270}
}

func ValidateCardanKey(key []int, gridSize int) error {
	if gridSize <= 0 {
		return fmt.Errorf("invalid gridSize provided: %d", gridSize)
	}

	maxIndex := gridSize * gridSize
	centerIndex := -1

	if gridSize%2 != 0 {
		center := point{gridSize / 2, gridSize / 2}
		centerIndex = pointToIndex(center, gridSize)
	}

	expectedKeyLen := (maxIndex - gridSize%2) / 4
	if len(key) != expectedKeyLen {
		return fmt.Errorf("invalid key length: got %d, expected %d for a %dx%d grid",
			len(key), expectedKeyLen, gridSize, gridSize)
	}

	for _, index := range key {
		if index < 0 || index >= maxIndex {
			return fmt.Errorf("key index out of bounds: %d, max: %d", index, maxIndex-1)
		}

		if index == centerIndex {
			return fmt.Errorf("index %d is the center of an odd grid and cannot be a part of the key", index)
		}
	}

	seen := make(map[int]bool)
	for _, index := range key {
		if seen[index] {
			return fmt.Errorf("duplicate indexes provided: %d", index)
		}
		seen[index] = true
	}

	covered := make(map[int]struct{})
	for _, index := range key {
		p := indexToPoint(index, gridSize)
		rotations := getAllRotations(p, gridSize)

		for _, rpoint := range rotations {
			rotationIndex := pointToIndex(rpoint, gridSize)
			if _, exists := covered[rotationIndex]; exists {
				return fmt.Errorf("index overlap! the key is invalid!")
			}
			covered[rotationIndex] = struct{}{}
		}
	}

	expectedCoverage := maxIndex - gridSize%2
	if len(covered) != expectedCoverage {
		return fmt.Errorf("incomplete coverage: %d of %d cells covered", len(covered), expectedCoverage)
	}

	return nil
}

func GenerateCardanKey(gridSize int) ([]int, error) {
	if gridSize <= 0 {
		return nil, fmt.Errorf("invalid gridSize provided: %d", gridSize)
	}

	key := make([]int, (gridSize*gridSize-gridSize%2)/4)
	keyIndex := 0
	for i := range gridSize/2 + gridSize%2 {
		for j := range gridSize/2 + gridSize%2 {
			p := point{i, j}
			if p.row == gridSize/2 && p.col == gridSize/2 {
				continue // Skip the center
			}

			allRotations := getAllRotations(p, gridSize)
			randomIndex := rand.IntN(len(allRotations))
			key[keyIndex] = pointToIndex(allRotations[randomIndex], gridSize)
			keyIndex++
		}
	}
	return key, nil
}

func NewCardanCipher(key []int, gridSize int) (*CardanCipher, error) {
	if gridSize <= 0 {
		return nil, fmt.Errorf("invalid gridSize provided: %d", gridSize)
	}

	if key == nil {
		var err error
		key, err = GenerateCardanKey(gridSize)
		if err != nil {
			return nil, err
		}
	} else if err := ValidateCardanKey(key, gridSize); err != nil {
		return nil, err
	}

	sortedKey := make([]int, len(key))
	copy(sortedKey, key)
	slices.Sort(sortedKey)

	permutationTable := make([]int, gridSize*gridSize)
	inverseTable := make([]int, gridSize*gridSize)
	for i := range 4 {
		for j, index := range sortedKey {
			permutationTable[i*len(sortedKey)+j] = index
			inverseTable[index] = i*len(sortedKey) + j
			// Rotate the key in-place
			sortedKey[j] = pointToIndex(rotate90(indexToPoint(index, gridSize), gridSize), gridSize)
		}
	}

	// Set the last element to center in an odd grid
	if gridSize%2 != 0 {
		center := pointToIndex(point{gridSize / 2, gridSize / 2}, gridSize)
		permutationTable[len(permutationTable)-1] = center
		inverseTable[center] = len(permutationTable) - 1
	}

	return &CardanCipher{
		PermutationTable: permutationTable,
		InverseTable:     inverseTable,
	}, nil
}

func (cCipher *CardanCipher) IsInPlace() bool {
	return false
}

func (cCipher *CardanCipher) EncryptBlock(dst []byte, src []byte) error {
	blockSize := len(cCipher.PermutationTable)
	if len(src) != blockSize || len(dst) != blockSize {
		return fmt.Errorf("block size mismatch: expected %d, got src=%d dst=%d", blockSize, len(src), len(dst))
	}

	for i := range len(dst) {
		dst[cCipher.PermutationTable[i]] = src[i]
	}

	return nil
}

func (cCipher *CardanCipher) DecryptBlock(dst []byte, src []byte) error {
	blockSize := len(cCipher.PermutationTable)
	if len(src) != blockSize || len(dst) != blockSize {
		return fmt.Errorf("block size mismatch: expected %d, got src=%d dst=%d", blockSize, len(src), len(dst))
	}

	for i := range len(dst) {
		dst[cCipher.InverseTable[i]] = src[i]
	}

	return nil
}
