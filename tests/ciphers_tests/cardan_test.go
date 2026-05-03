package ciphers_test

import (
	"bytes"
	"testing"

	"github.com/ItakawaM/arcipher/ciphers"
)

func TestValidateCardanKey(t *testing.T) {
	tests := []struct {
		name    string
		gridKey *ciphers.CardanKey
		wantErr bool
	}{
		{
			name: "valid key 1",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1,
			}},
			wantErr: false,
		},
		{
			name: "valid key 2",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 10, 8, 11,
			}},
			wantErr: false,
		},
		{
			name: "invalid key length 1",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 2,
			}},
			wantErr: true,
		},
		{
			name: "invalid key length 2",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 2, 3, 4,
			}},
			wantErr: true,
		},
		{
			name: "out of bounds key index",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 10,
			}},
			wantErr: true,
		},
		{
			name: "key includes center index",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 4,
			}},
			wantErr: true,
		},
		{
			name: "key includes duplicate indexes",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 4,
			}},
			wantErr: true,
		},
		{
			name: "key includes overlapping indexes 1",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 2,
			}},
			wantErr: true,
		},
		{
			name: "key includes overlapping indexes 2",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 2,
			}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := ciphers.ValidateCardanKey(tt.gridKey)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ValidateCardanKey() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("ValidateCardanKey() succeeded unexpectedly")
			}
		})
	}
}

func TestGenerateCardanKey(t *testing.T) {
	tests := []struct {
		name     string
		gridSize int
		wantErr  bool
	}{
		{
			name:     "valid gridsize 1",
			gridSize: 5,
			wantErr:  false,
		},
		{
			name:     "valid gridsize 2",
			gridSize: 6,
			wantErr:  false,
		},
		{
			name:     "invalid gridsize 1",
			gridSize: 0,
			wantErr:  true,
		},
		{
			name:     "invalid gridsize 2",
			gridSize: -1,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := ciphers.GenerateCardanKey(tt.gridSize)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("GenerateCardanKey() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("GenerateCardanKey() succeeded unexpectedly")
			}

			if err := ciphers.ValidateCardanKey(got); err != nil {
				t.Errorf("GenerateCardanKey() = %v, not valid, want something valid", got)
			}
		})
	}
}

func TestNewCardanCipher(t *testing.T) {
	tests := []struct {
		name    string
		gridKey *ciphers.CardanKey
		wantErr bool
	}{
		{
			name: "valid key and gridsize 1",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1,
			}},
			wantErr: false,
		},
		{
			name: "valid key and gridsize 2",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 5,
			}},
			wantErr: false,
		},
		{
			name: "valid key 3",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 6,
			}},
			wantErr: false,
		},
		{
			name: "invalid key 1",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 5, 10,
			}},
			wantErr: true,
		},
		{
			name: "invalid key 2",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 4,
			}},
			wantErr: true,
		},
		{
			name:    "nil key",
			gridKey: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := ciphers.NewCardanCipher(tt.gridKey)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("NewCardanCipher() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("NewCardanCipher() succeeded unexpectedly")
			}
		})
	}
}

func TestCardanCipher_EncryptBlock(t *testing.T) {
	tests := []struct {
		name    string
		gridKey *ciphers.CardanKey
		dst     []byte
		src     []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "normal 1",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1,
			}},
			src:  []byte("ninechars"),
			dst:  make([]byte, 3*3),
			want: []byte("ninaserch"),
		},
		{
			name: "normal 2",
			gridKey: &ciphers.CardanKey{Key: []int{
				3, 6, 8, 13,
			}},
			src:  []byte("mamamylaramurano"),
			dst:  make([]byte, 16),
			want: []byte("rmrmyaaammlnuaoa"),
		},
		{
			name: "dst src size mismatch 1",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 5,
			}},
			src:     []byte("helloworld"),
			dst:     make([]byte, 3),
			wantErr: true,
		},
		{
			name: "dst src size mismatch 2",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 5,
			}},
			src:     []byte("helloworld"),
			dst:     make([]byte, 16),
			wantErr: true,
		},
		{
			name: "dst src size mismatch 3",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 5,
			}},
			src:     []byte("helloworld      "),
			dst:     make([]byte, 17),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ccipher, err := ciphers.NewCardanCipher(tt.gridKey)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := ccipher.EncryptBlock(tt.dst, tt.src)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("EncryptBlock() failed: %v", gotErr)
				}
				return
			}

			if !bytes.Equal(tt.dst, tt.want) {
				t.Errorf("Encrypt = %q, want %q", (tt.dst), (tt.want))
			}
		})
	}
}

func TestCardanCipher_DecryptBlock(t *testing.T) {
	tests := []struct {
		name    string
		gridKey *ciphers.CardanKey
		dst     []byte
		src     []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "normal 1",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1,
			}},
			src:  []byte("ninaserch"),
			dst:  make([]byte, 3*3),
			want: []byte("ninechars"),
		},
		{
			name: "normal 2",
			gridKey: &ciphers.CardanKey{Key: []int{
				3, 6, 8, 13,
			}},
			src:  []byte("rmrmyaaammlnuaoa"),
			dst:  make([]byte, 16),
			want: []byte("mamamylaramurano"),
		},
		{
			name: "dst src size mismatch 1",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 5,
			}},
			src:     []byte("helloworld"),
			dst:     make([]byte, 3),
			wantErr: true,
		},
		{
			name: "dst src size mismatch 2",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 5,
			}},
			src:     []byte("helloworld"),
			dst:     make([]byte, 16),
			wantErr: true,
		},
		{
			name: "dst src size mismatch 3",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 4, 5,
			}},
			src:     []byte("helloworld      "),
			dst:     make([]byte, 17),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ccipher, err := ciphers.NewCardanCipher(tt.gridKey)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := ccipher.DecryptBlock(tt.dst, tt.src)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("DecryptBlock() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("DecryptBlock() succeeded unexpectedly")
			}

			if !bytes.Equal(tt.dst, tt.want) {
				t.Errorf("DecryptBlock() got %q, want %q", tt.dst, tt.want)
			}
		})
	}
}

func TestCardanCipher_Rountrip(t *testing.T) {
	tests := []struct {
		name     string
		gridSize int
		gridKey  *ciphers.CardanKey
		message  string
	}{
		{
			name: "normal 1",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1,
			}},
			message: "hellodoge",
		},
		{
			name: "normal 2",
			gridKey: &ciphers.CardanKey{Key: []int{
				0, 1, 2, 5,
			}},
			message: "catDogcat1catcat",
		},
		{
			name:     "random 1",
			gridSize: 2,
			gridKey:  nil,
			message:  "abcd",
		},
		{
			name:     "random 2",
			gridSize: 3,
			gridKey:  nil,
			message:  "abcdefghi",
		},
		{
			name:     "random 3",
			gridSize: 4,
			gridKey:  nil,
			message:  "abcdefghiabcdefg",
		},
		{
			name:     "random 4",
			gridSize: 5,
			gridKey:  nil,
			message:  "abcdefghiabcdefgabcdefghi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.gridKey == nil {
				var err error
				tt.gridKey, err = ciphers.GenerateCardanKey(tt.gridSize)
				if err != nil {
					t.Fatalf("could not generate key: %v", err)
				}
			}

			ccipher, err := ciphers.NewCardanCipher(tt.gridKey)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			src := []byte(tt.message)
			dst := make([]byte, len(src))

			if err := ccipher.EncryptBlock(dst, src); err != nil {
				t.Fatalf("EncryptBlock() failed: %v", err)
			}
			if err := ccipher.DecryptBlock(src, dst); err != nil {
				t.Fatalf("DecryptBlock() failed: %v", err)
			}

			if string(src) != tt.message {
				t.Errorf("Roundtrip = %s, want %s", string(src), tt.message)
			}
		})
	}
}
