package ciphers

import (
	"encoding/json"
	"fmt"
	"slices"
)

/*
CardanCipher is a grille-based transposition cipher that uses a rotating grid (Cardan grille)
to encrypt messages.

The cipher works by placing holes in a grid pattern and rotating
the grid four times to mark which positions are "holes".
*/
type CardanCipher struct {
	PermutationTable []int
}

/*
CardanKey represents the key for a Cardan grille cipher.

It contains a list of indexes that form the initial hole pattern.
*/
type CardanKey struct {
	Key []int `json:"key"`
}

/*
String returns a JSON string representation of the CardanKey.

If JSON string representation fails falls back to fmt.Sprintf formatting.
*/
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

/*
ValidateCardanKey validates that a CardanKey is valid for the given grid size.

It checks if:
 1. the key has the correct length
 2. all indices are in bounds,
 3. there are no duplicates
 4. there are no overlaps when rotated
 5. all non-center cells are covered.

Returns an error if the key is invalid.
*/
func ValidateCardanKey(gridKey *CardanKey, gridSize int) error {
	if gridSize <= 0 {
		return fmt.Errorf("invalid gridSize provided: %d", gridSize)
	}
	key := gridKey.Key

	maxIndex := gridSize * gridSize
	centerIndex := -1

	if gridSize%2 != 0 {
		centerIndex = (maxIndex - 1) / 2
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
				return fmt.Errorf("index overlap: the key is invalid")
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

/*
GenerateCardanKey generates a random valid CardanKey for the given grid size.

The grid size must be positive.

Returns an error if key generation fails.
*/
func GenerateCardanKey(gridSize int) (*CardanKey, error) {
	if gridSize <= 0 {
		return nil, fmt.Errorf("invalid gridSize provided: %d", gridSize)
	}

	keyLength := (gridSize*gridSize - gridSize%2) / 4
	key := make([]int, keyLength)

	keyIndex := 0
	rotations, err := RandSequenceIntMaxN(4, keyLength)
	if err != nil {
		return nil, err
	}

	for i := range gridSize / 2 {
		for j := range gridSize/2 + gridSize%2 {
			index := i*gridSize + j
			if i == gridSize/2 && j == gridSize/2 {
				continue // Skip the center
			}

			allRotations := getAllRotations(index, gridSize)
			randomIndex := <-rotations
			key[keyIndex] = allRotations[randomIndex]
			keyIndex++
		}
	}

	return &CardanKey{Key: key}, nil
}

/*
NewCardanCipher creates a new Cardan cipher with the given key and grid size.

The gridSize must be positive.

If gridKey is nil, a random key will be generated.

If gridKey is provided, it will be validated first.

The key is not saved.

Returns an error if gridSize is invalid or the key is invalid.
*/
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
	for i := range 4 {
		for j, index := range sortedKey {
			permutationTable[i*len(sortedKey)+j] = index
			// Rotate the key in-place
			sortedKey[j] = rotate90(index, gridSize)
		}
		slices.Sort(sortedKey)
	}

	// Set the last element to center in an odd grid
	if gridSize%2 != 0 {
		center := (gridSize*gridSize - 1) / 2
		permutationTable[len(permutationTable)-1] = center
	}

	return &CardanCipher{
		PermutationTable: permutationTable,
	}, nil
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Cardan cipher does not support in-place operations since bytes are written
to non-sequential positions, requiring a separate destination buffer.
*/
func (cCipher *CardanCipher) IsInPlace() bool {
	return false
}

/*
EncryptBlock encrypts src using the Cardan cipher and writes the result to dst.

src and dst cannot alias.

src and dst must be the same length and must match gridSize*gridSize.
*/
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

/*
DecryptBlock decrypts src using the Cardan cipher and writes the result to dst.

src and dst cannot alias.

src and dst must be the same length and must match gridSize*gridSize.
*/
func (cCipher *CardanCipher) DecryptBlock(dst []byte, src []byte) error {
	blockSize := len(cCipher.PermutationTable)
	if len(src) != blockSize || len(dst) != blockSize {
		return fmt.Errorf("block size mismatch: expected %d, got src=%d dst=%d", blockSize, len(src), len(dst))
	}

	for i := range len(dst) {
		dst[i] = src[cCipher.PermutationTable[i]]
	}

	return nil
}
