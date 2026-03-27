package ciphers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
)

type CardanCipher struct {
	PermutationTable []int
	InverseTable     []int
}

type CardanKey struct {
	Key []int `json:"key"`
}

func (cK *CardanKey) String() string {
	jsonData, err := json.Marshal(cK)
	if err != nil {
		return fmt.Sprintf("CardanKey{Key: %v}", cK.Key)
	}

	return string(jsonData)
}

func rotate90(index int, gridSize int) int {
	row := index / gridSize
	col := index % gridSize

	return col*gridSize + (gridSize - 1 - row)
}

func getAllRotations(index int, gridSize int) [4]int {
	rotation90 := rotate90(index, gridSize)
	rotation180 := rotate90(rotation90, gridSize)
	rotation270 := rotate90(rotation180, gridSize)

	return [4]int{index, rotation90, rotation180, rotation270}
}

func ValidateCardanKey(gridKey *CardanKey, gridSize int) error {
	if gridSize <= 0 {
		return fmt.Errorf("invalid gridSize provided: %d", gridSize)
	}
	key := gridKey.Key

	maxIndex := gridSize * gridSize
	centerIndex := -1

	if gridSize%2 != 0 {
		centerIndex = (gridSize - 1) / 2
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
		rotations := getAllRotations(index, gridSize)
		for _, rotationIndex := range rotations {
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

func GenerateCardanKey(gridSize int) (*CardanKey, error) {
	if gridSize <= 0 {
		return nil, fmt.Errorf("invalid gridSize provided: %d", gridSize)
	}

	key := make([]int, (gridSize*gridSize-gridSize%2)/4)
	keyIndex := 0
	for i := range gridSize / 2 {
		for j := range gridSize/2 + gridSize%2 {
			index := i*gridSize + j
			if i == gridSize/2 && j == gridSize/2 {
				continue // Skip the center
			}

			allRotations := getAllRotations(index, gridSize)
			randomIndex, err := cryptoRandN(len(allRotations))
			if err != nil {
				return nil, fmt.Errorf("failed to generate random index: %w", err)
			}
			key[keyIndex] = allRotations[randomIndex]
			keyIndex++
		}
	}
	return &CardanKey{key}, nil
}

func cryptoRandN(n int) (int, error) {
	bigN := big.NewInt(int64(n))
	val, err := rand.Int(rand.Reader, bigN)
	if err != nil {
		return 0, err
	}
	return int(val.Int64()), nil
}

func NewCardanCipher(gridKey *CardanKey, gridSize int) (*CardanCipher, error) {
	if gridSize <= 0 {
		return nil, fmt.Errorf("invalid gridSize provided: %d", gridSize)
	}

	if gridKey == nil {
		var err error
		gridKey, err = GenerateCardanKey(gridSize)
		if err != nil {
			return nil, err
		}
	} else if err := ValidateCardanKey(gridKey, gridSize); err != nil {
		return nil, err
	}

	sortedKey := make([]int, len(gridKey.Key))
	copy(sortedKey, gridKey.Key)
	slices.Sort(sortedKey)

	permutationTable := make([]int, gridSize*gridSize)
	inverseTable := make([]int, gridSize*gridSize)
	for i := range 4 {
		for j, index := range sortedKey {
			permutationTable[i*len(sortedKey)+j] = index
			inverseTable[index] = i*len(sortedKey) + j
			// Rotate the key in-place
			sortedKey[j] = rotate90(index, gridSize)
		}
	}

	// Set the last element to center in an odd grid
	if gridSize%2 != 0 {
		center := (gridSize - 1) / 2
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
