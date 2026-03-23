package ciphers_test

import (
	"bytes"
	"testing"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

func TestValidateCardanKey(t *testing.T) {
	validKey4x4 := &ciphers.CardanKey{Key: []int{0, 1, 4, 5}}
	validKey6x6, _ := ciphers.GenerateCardanKey(6)

	tests := []struct {
		name     string
		gridKey  *ciphers.CardanKey
		gridSize int
		wantErr  bool
	}{
		{"Valid 4x4 Grid Key", validKey4x4, 4, false},
		{"Valid 6x6 Grid Key", validKey6x6, 6, false},
		{"Invalid GridSize Zero", &ciphers.CardanKey{Key: []int{0, 1}}, 0, true},
		{"Invalid GridSize Negative", &ciphers.CardanKey{Key: []int{0, 1}}, -1, true},
		{"Invalid Key Length Too Short", &ciphers.CardanKey{Key: []int{0}}, 4, true},
		{"Invalid Key Index Out of Bounds", &ciphers.CardanKey{Key: []int{0, 1, 4, 20}}, 4, true},
		{"Invalid Duplicate Index", &ciphers.CardanKey{Key: []int{0, 1, 1, 5}}, 4, true},
		{"Invalid Center Index on Odd Grid", &ciphers.CardanKey{Key: []int{0, 1, 4, 5, 8, 9, 10, 11, 12, 13, 14}}, 5, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ciphers.ValidateCardanKey(tt.gridKey, tt.gridSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCardanKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateCardanKey(t *testing.T) {
	tests := []struct {
		name     string
		gridSize int
		wantErr  bool
		wantLen  int
	}{
		{"Valid 2x2", 2, false, 1},
		{"Valid 4x4", 4, false, 4},
		{"Valid 6x6", 6, false, 9},
		{"Valid 8x8", 8, false, 16},
		{"Invalid Zero", 0, true, 0},
		{"Invalid Negative", -1, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ciphers.GenerateCardanKey(tt.gridSize)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateCardanKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if key == nil {
				t.Fatal("Expected non-nil key")
			}

			if len(key.Key) != tt.wantLen {
				t.Errorf("Expected key length %d, got %d", tt.wantLen, len(key.Key))
			}

			if err := ciphers.ValidateCardanKey(key, tt.gridSize); err != nil {
				t.Errorf("Generated key is invalid: %v", err)
			}
		})
	}
}

func TestCardanCipher(t *testing.T) {
	cipher, err := ciphers.NewCardanCipher(nil, 4)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	tests := []struct {
		name    string
		message []byte
	}{
		{"Full Block 16 bytes", []byte("HellWorldHelloW!")},
		{"Single Block Exact", []byte("HellWorldHelloW!")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := tt.message
			dst := make([]byte, len(src))
			result := make([]byte, len(src))

			if err := cipher.EncryptBlock(dst, src); err != nil {
				t.Fatalf("EncryptBlock() error = %v", err)
			}

			if err := cipher.DecryptBlock(result, dst); err != nil {
				t.Fatalf("DecryptBlock() error = %v", err)
			}

			if !bytes.Equal(result, src) {
				t.Errorf("Round trip failed: want %q, got %q", src, result)
			}
		})
	}
}
