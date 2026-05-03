package ciphers

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
)

/*
CardanCipher is a grille-based transposition cipher that uses a rotating grid (Cardan grille)
to encrypt messages.

The cipher works by placing holes in a grid pattern and rotating
the grid four times to mark which positions are "holes".
*/
type CardanCipher struct {
	gridKey          []int
	permutationTable []int
}

/*
CardanKey represents the key for a Cardan grille cipher.

It contains a list of indexes that form the initial hole pattern.
*/
type CardanKey struct {
	Key []int `json:"key"`
}

/*
Key returns the underlying gridKey Cardan Cipher uses to construct a permutation.
*/
func (cc *CardanCipher) Key() CardanKey {
	return CardanKey{
		Key: cc.gridKey,
	}
}

/*
String returns a JSON string representation of the CardanKey.

If JSON string representation fails falls back to fmt.Sprintf formatting.
*/
func (ck *CardanKey) String() string {
	jsonData, err := json.Marshal(ck)
	if err != nil {
		return fmt.Sprintf("CardanKey{Key: %v}", ck.Key)
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
func ValidateCardanKey(gridKey *CardanKey) error {
	key := gridKey.Key
	gridSize, err := CalculateGridSize(len(key))
	if err != nil {
		return err
	}

	maxIndex := gridSize * gridSize
	centerIndex := -1

	if gridSize%2 != 0 {
		centerIndex = (maxIndex - 1) / 2
	}

	seen := make(map[int]bool)
	for _, index := range key {
		if index < 0 || index >= maxIndex {
			return fmt.Errorf("key index out of bounds: %d, max: %d", index, maxIndex-1)
		}

		if index == centerIndex {
			return fmt.Errorf("index %d is the center of an odd grid and cannot be a part of the key", index)
		}

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
CalculateGridSize calculates the size of the grid used
based on the provided gridKeyLen.

Return an error if gridKeyLen does not correspond to any valid grid size.
*/
func CalculateGridSize(gridKeyLen int) (int, error) {
	for _, candidate := range []int{
		int(math.Round(math.Sqrt(float64(4 * gridKeyLen)))),
		int(math.Round(math.Sqrt(float64(4*gridKeyLen + 1)))),
	} {
		if candidate > 0 && (candidate*candidate-candidate%2)/4 == gridKeyLen {
			return candidate, nil
		}
	}

	return 0, fmt.Errorf("key length %d does not correspond to any valid grid size", gridKeyLen)
}

/*
NewCardanCipher creates a new Cardan cipher with the given key.

Returns an error if the key is invalid.
*/
func NewCardanCipher(gridKey *CardanKey) (*CardanCipher, error) {
	if gridKey == nil {
		return nil, fmt.Errorf("gridKey must not be nil")
	}

	gridSize, err := CalculateGridSize(len(gridKey.Key))
	if err != nil {
		return nil, err
	}

	if err := ValidateCardanKey(gridKey); err != nil {
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
		permutationTable: permutationTable,
		gridKey:          gridKey.Key,
	}, nil
}

/*
IsInPlace returns whether the cipher can perform encryption/decryption in-place.

Cardan cipher does not support in-place operations since bytes are written
to non-sequential positions, requiring a separate destination buffer.
*/
func (cc *CardanCipher) IsInPlace() bool {
	return false
}

/*
EncryptBlock encrypts src using the Cardan cipher and writes the result to dst.

src and dst cannot alias.

src and dst must be the same length and must match gridSize*gridSize.
*/
func (cc *CardanCipher) EncryptBlock(dst []byte, src []byte) error {
	blockSize := len(cc.permutationTable)
	if len(src) != blockSize || len(dst) != blockSize {
		return fmt.Errorf("block size mismatch: expected %d, got src=%d dst=%d", blockSize, len(src), len(dst))
	}

	for i := range len(dst) {
		dst[cc.permutationTable[i]] = src[i]
	}

	return nil
}

/*
DecryptBlock decrypts src using the Cardan cipher and writes the result to dst.

src and dst cannot alias.

src and dst must be the same length and must match gridSize*gridSize.
*/
func (cc *CardanCipher) DecryptBlock(dst []byte, src []byte) error {
	blockSize := len(cc.permutationTable)
	if len(src) != blockSize || len(dst) != blockSize {
		return fmt.Errorf("block size mismatch: expected %d, got src=%d dst=%d", blockSize, len(src), len(dst))
	}

	for i := range len(dst) {
		dst[i] = src[cc.permutationTable[i]]
	}

	return nil
}
