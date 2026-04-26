package ciphers_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/ItakawaM/arcipher/ciphers"
)

func TestNewAffineCipher(t *testing.T) {
	tests := []struct {
		name        string
		key         *ciphers.AffineKey
		wantInverse *ciphers.AffineKey
		wantErr     bool
	}{
		{
			name: "valid key 1",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{6, 24, 1},
					{13, 16, 10},
					{20, 17, 15},
				},
				VectorKey: []int{3, 7, 11},
			},
			wantInverse: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{8, 5, 10},
					{21, 8, 21},
					{21, 12, 8},
				},
				VectorKey: []int{3, 7, 11},
			},
		},
		{
			name: "valid key 2",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{22, 3},
					{9, 6},
				},
				VectorKey: []int{0, 13},
			},
			wantInverse: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{6, 23},
					{17, 22},
				},
				VectorKey: []int{0, 13},
			},
		},
		{
			name: "valid key with out-of-range vector",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{6, 24, 1},
					{13, 16, 10},
					{20, 17, 15},
				},
				VectorKey: []int{29, 0, 52},
			},
			wantInverse: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{8, 5, 10},
					{21, 8, 21},
					{21, 12, 8},
				},
				VectorKey: []int{3, 0, 0},
			},
		},
		{
			name: "empty key",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{},
				VectorKey: []int{},
			},
			wantErr: true,
		},
		{
			name: "non-square matrix",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{1, 2},
				},
				VectorKey: []int{0},
			},
			wantErr: true,
		},
		{
			name: "ragged matrix",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{1, 2},
					{},
				},
				VectorKey: []int{0, 0},
			},
			wantErr: true,
		},
		{
			name: "not invertible mod 26",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{1, 1},
					{1, 1},
				},
				VectorKey: []int{0, 0},
			},
			wantErr: true,
		},
		{
			name: "vector length mismatch",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{6, 24, 1},
					{13, 16, 10},
					{20, 17, 15},
				},
				VectorKey: []int{1, 2},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := ciphers.NewAffineCipher(tt.key)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("NewAffineCipher() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("NewAffineCipher() succeeded unexpectedly")
			}

			gotKey := got.Key()
			gotInverse := got.InverseKey()

			matrixMatch := slices.EqualFunc(gotKey.MatrixKey, tt.key.MatrixKey, slices.Equal)
			inverseMatch := slices.EqualFunc(gotInverse.MatrixKey, tt.wantInverse.MatrixKey, slices.Equal)
			vectorMatch := slices.Equal(gotKey.VectorKey, tt.wantInverse.VectorKey)

			if !matrixMatch || !inverseMatch || !vectorMatch {
				t.Errorf("NewAffineCipher() key = %v vector = %v inverse = %v, want key = %v vector = %v inverse = %v",
					gotKey.MatrixKey, gotKey.VectorKey, gotInverse.MatrixKey,
					tt.key.MatrixKey, tt.wantInverse.VectorKey, tt.wantInverse.MatrixKey)
			}
		})
	}
}

func TestGenerateAffineKey(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{
			name: "size 1",
			size: 1,
		},
		{
			name: "size 3",
			size: 3,
		},
		{
			name: "size 10",
			size: 10,
		},
		{
			name: "big 1",
			size: 25,
		},
		{
			name: "big 2",
			size: 97,
		},
		{
			name:    "zero",
			size:    0,
			wantErr: true,
		},
		{
			name:    "negative size 1",
			size:    -1,
			wantErr: true,
		},
		{
			name:    "negative size 2",
			size:    -23,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := ciphers.GenerateAffineKey(tt.size)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("GenerateAffineKey() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("GenerateAffineKey() succeeded unexpectedly")
			}

			if _, err := ciphers.NewAffineCipher(got); err != nil {
				t.Errorf("GenerateAffineKey() produced unusable key: %v", err)
			}
		})
	}
}

func TestAffineCipher_EncryptBlock(t *testing.T) {
	tests := []struct {
		name    string
		key     *ciphers.AffineKey
		dst     []byte
		src     []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "zero vector key",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{25, 5, 18},
					{25, 20, 20},
					{22, 0, 11},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:  []byte("Doggiecat"),
			dst:  make([]byte, 9),
			want: []byte("Thccaucot"),
		},
		{
			name: "zero vector key 2x2",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{4, 1},
					{13, 25},
				},
				VectorKey: []int{0, 0},
			},
			src:  []byte("helloWORLD"),
			dst:  make([]byte, 10),
			want: []byte("gjdcaEVJVK"),
		},
		{

			name: "nonzero vector key",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{1, 2, 3},
			},
			src:  []byte("dog"),
			dst:  make([]byte, 3),
			want: []byte("aay"),
		},
		{
			name: "leftover and non-alpha characters",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:  []byte("my dog LOVES tenniSS"),
			dst:  make([]byte, 20),
			want: []byte("jk ire IKXPE vdrviSS"),
		},
		{
			name: "leftover characters 2",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:  []byte("hello world, MUCHACHOO!"),
			dst:  make([]byte, 23),
			want: []byte("qoxbk pbrhd, MVWZLQNZO!"),
		},
		{
			name: "empty src and dst",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:  []byte{},
			dst:  []byte{},
			want: []byte{},
		},
		{
			name: "dst larger than src",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:     []byte("abc"),
			dst:     make([]byte, 5),
			wantErr: true,
		},
		{
			name: "dst smaller than src",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:     []byte("abc"),
			dst:     make([]byte, 1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac, err := ciphers.NewAffineCipher(tt.key)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := ac.EncryptBlock(tt.dst, tt.src)
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
				t.Errorf("EncryptBlock() = %q, want %q", tt.dst, tt.want)
			}
		})
	}
}

func TestAffineCipher_DecryptBlock(t *testing.T) {
	tests := []struct {
		name    string
		key     *ciphers.AffineKey
		dst     []byte
		src     []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "zero vector key",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{25, 5, 18},
					{25, 20, 20},
					{22, 0, 11},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:  []byte("thccaucot"),
			dst:  make([]byte, 9),
			want: []byte("doggiecat"),
		},
		{
			name: "zero vector key 2x2",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{4, 1},
					{13, 25},
				},
				VectorKey: []int{0, 0},
			},
			src:  []byte("gjdcaevjvk"),
			dst:  make([]byte, 10),
			want: []byte("helloworld"),
		},
		{
			name: "nonzero vector key",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{1, 2, 3},
			},
			src:  []byte("aay"),
			dst:  make([]byte, 3),
			want: []byte("dog"),
		},
		{
			name: "leftover and non-alpha characters",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:  []byte("jk ire IKXPE vdrviSS"),
			dst:  make([]byte, 20),
			want: []byte("my dog LOVES tenniSS"),
		},
		{
			name: "leftover characters 2",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:  []byte("qoxbk pbrhd, MVWZLQNZO!"),
			dst:  make([]byte, 23),
			want: []byte("hello world, MUCHACHOO!"),
		},
		{
			name: "empty src and dst",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:  []byte{},
			dst:  []byte{},
			want: []byte{},
		},
		{
			name: "dst larger than src",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:     []byte("abc"),
			dst:     make([]byte, 5),
			wantErr: true,
		},
		{
			name: "dst smaller than src",
			key: &ciphers.AffineKey{
				MatrixKey: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
				VectorKey: []int{0, 0, 0},
			},
			src:     []byte("abc"),
			dst:     make([]byte, 1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac, err := ciphers.NewAffineCipher(tt.key)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := ac.DecryptBlock(tt.dst, tt.src)
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
				t.Errorf("DecryptBlock() = %q, want %q", tt.dst, tt.want)
			}
		})
	}
}

func TestAffineCipher_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		count   int
		message string
	}{
		{
			name:    "normal 1",
			size:    3,
			count:   10,
			message: "hello world, I love dogs!",
		},
		{
			name:    "normal 2",
			size:    4,
			count:   10,
			message: "it's go, not golang",
		},
		{
			name:    "normal 3",
			size:    2,
			count:   10,
			message: "cat womp womp",
		},
		{
			name:    "normal 4",
			size:    9,
			count:   5,
			message: "dog womp womp",
		},
		{
			name:    "scalar affine",
			size:    1,
			count:   10,
			message: "the quick brown fox jumps over the lazy dog",
		},
		{
			name:    "big 1",
			size:    25,
			count:   3,
			message: "Reference site about Lorem Ipsum, giving information on its origins, as well as a random Lipsum generator.",
		},
		{
			name:    "big 2",
			size:    15,
			count:   5,
			message: "A handy Lorem Ipsum Generator that helps to create dummy text for all layout needs.",
		},
		{
			name:    "big 3",
			size:    30,
			count:   5,
			message: "The method requires carrying out elementary operations on the rows of the matrix M in order to bring it back to the identity matrix. To obtain the inverse matrix, perform the same operations but this time from the identity matrix.",
		},
	}

	for _, tt := range tests {
		for range tt.count {
			t.Run(tt.name, func(t *testing.T) {
				key, _ := ciphers.GenerateAffineKey(tt.size)
				cipher, _ := ciphers.NewAffineCipher(key)
				src := []byte(tt.message)
				dst := make([]byte, len(src))

				if err := cipher.EncryptBlock(dst, src); err != nil {
					t.Fatalf("EncryptBlock() failed: %v", err)
				}
				if err := cipher.DecryptBlock(src, dst); err != nil {
					t.Fatalf("DecryptBlock() failed: %v", err)
				}

				if string(src) != tt.message {
					t.Errorf("RoundTrip() = %s, want %s", string(src), tt.message)
				}
			})
		}
	}
}
