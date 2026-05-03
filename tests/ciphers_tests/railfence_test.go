package ciphers_test

import (
	"bytes"
	"testing"

	"github.com/ItakawaM/arcipher/ciphers"
)

func TestNewRailFenceCipher(t *testing.T) {
	tests := []struct {
		name              string
		key               int
		permutationLength int
		wantErr           bool
	}{
		{
			name:              "valid key 1",
			key:               3,
			permutationLength: 5,
		},
		{
			name:              "valid key 2",
			key:               2,
			permutationLength: 10,
		},
		{
			name:              "reverse",
			key:               123,
			permutationLength: 10,
		},
		{
			name:              "no change",
			key:               1,
			permutationLength: 3,
		},
		{
			name:              "invalid key 1",
			key:               0,
			permutationLength: 123,
			wantErr:           true,
		},
		{
			name:              "invalid permutationLength 2",
			key:               1,
			permutationLength: -1,
			wantErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := ciphers.NewRailFenceCipher(&ciphers.RailFenceKey{
				Key:               tt.key,
				PermutationLength: tt.permutationLength,
			})
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("NewRailFenceCipher() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("NewRailFenceCipher() succeeded unexpectedly")
			}
		})
	}
}

func TestRailFenceCipher_EncryptBlock(t *testing.T) {
	tests := []struct {
		name              string
		key               int
		permutationLength int
		dst               []byte
		src               []byte
		want              []byte
		wantErr           bool
	}{
		{
			name:              "normal 1",
			key:               3,
			permutationLength: 5,
			src:               []byte("helLo"),
			dst:               make([]byte, 5),
			want:              []byte("leLho"),
		},
		{
			name:              "normal 2",
			key:               2,
			permutationLength: 10,
			src:               []byte("catDogcat1"),
			dst:               make([]byte, 10),
			want:              []byte("aDga1ctoct"),
		},
		{
			name:              "no change",
			key:               1,
			permutationLength: 10,
			src:               []byte("catDogcat1"),
			dst:               make([]byte, 10),
			want:              []byte("catDogcat1"),
		},
		{
			name:              "reverse",
			key:               10,
			permutationLength: 10,
			src:               []byte("catDogcat1"),
			dst:               make([]byte, 10),
			want:              []byte("1tacgoDtac"),
		},
		{
			name:              "dst src size mismatch 1",
			key:               3,
			permutationLength: 10,
			src:               []byte("helloworld"),
			dst:               make([]byte, 3),
			wantErr:           true,
		},
		{
			name:              "dst src size mismatch 2",
			key:               3,
			permutationLength: 10,
			src:               []byte("helloworld"),
			dst:               make([]byte, 12),
			wantErr:           true,
		},
		{
			name:              "dst src size mismatch 3",
			key:               3,
			permutationLength: 1,
			src:               []byte("helloworld"),
			dst:               make([]byte, 10),
			wantErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rfcipher, err := ciphers.NewRailFenceCipher(&ciphers.RailFenceKey{
				Key:               tt.key,
				PermutationLength: tt.permutationLength,
			})
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := rfcipher.EncryptBlock(tt.dst, tt.src)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("EncryptBlock() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("EncryptBlock() succeeded unexpectedly")
			}

			if !bytes.Equal(tt.dst, tt.want) {
				t.Errorf("Encrypt = %s, want %s", string(tt.dst), string(tt.want))
			}
		})
	}
}

func TestRailFenceCipher_DecryptBlock(t *testing.T) {
	tests := []struct {
		name              string
		key               int
		permutationLength int
		dst               []byte
		src               []byte
		want              []byte
		wantErr           bool
	}{
		{
			name:              "normal 1",
			key:               3,
			permutationLength: 5,
			src:               []byte("leLho"),
			dst:               make([]byte, 5),
			want:              []byte("helLo"),
		},
		{
			name:              "normal 2",
			key:               2,
			permutationLength: 10,
			src:               []byte("aDga1ctoct"),
			dst:               make([]byte, 10),
			want:              []byte("catDogcat1"),
		},
		{
			name:              "no change",
			key:               1,
			permutationLength: 10,
			src:               []byte("catDogcat1"),
			dst:               make([]byte, 10),
			want:              []byte("catDogcat1"),
		},
		{
			name:              "reverse",
			key:               10,
			permutationLength: 10,
			src:               []byte("1tacgoDtac"),
			dst:               make([]byte, 10),
			want:              []byte("catDogcat1"),
		},
		{
			name:              "dst src size mismatch 1",
			key:               3,
			permutationLength: 10,
			src:               []byte("helloworld"),
			dst:               make([]byte, 3),
			wantErr:           true,
		},
		{
			name:              "dst src size mismatch 2",
			key:               3,
			permutationLength: 10,
			src:               []byte("helloworld"),
			dst:               make([]byte, 12),
			wantErr:           true,
		},
		{
			name:              "dst src size mismatch 3",
			key:               3,
			permutationLength: 1,
			src:               []byte("helloworld"),
			dst:               make([]byte, 10),
			wantErr:           true,
		},
		{
			name:              "empty",
			key:               3,
			permutationLength: 10,
			src:               []byte{},
			dst:               []byte{},
			wantErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rfcipher, err := ciphers.NewRailFenceCipher(&ciphers.RailFenceKey{
				Key:               tt.key,
				PermutationLength: tt.permutationLength,
			})
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := rfcipher.DecryptBlock(tt.dst, tt.src)
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
				t.Errorf("Decrypt = %s, want %s", string(tt.dst), string(tt.want))
			}
		})
	}
}
