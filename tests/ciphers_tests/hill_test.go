package ciphers_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/ItakawaM/arcipher/ciphers"
)

func TestNewHillCipher(t *testing.T) {
	tests := []struct {
		name    string
		key     *ciphers.HillKey
		want    *ciphers.HillKey
		wantErr bool
	}{
		{
			name: "valid key 1",
			key: &ciphers.HillKey{
				Key: [][]int{
					{6, 24, 1},
					{13, 16, 10},
					{20, 17, 15},
				},
			},
			want: &ciphers.HillKey{
				Key: [][]int{
					{8, 5, 10},
					{21, 8, 21},
					{21, 12, 8},
				},
			},
		},
		{
			name: "valid key 2",
			key: &ciphers.HillKey{
				Key: [][]int{
					{22, 3},
					{9, 6},
				},
			},
			want: &ciphers.HillKey{
				Key: [][]int{
					{6, 23},
					{17, 22},
				},
			},
		},
		{
			name: "empty key",
			key: &ciphers.HillKey{
				Key: [][]int{},
			},
			wantErr: true,
		},
		{
			name: "invalid key 1",
			key: &ciphers.HillKey{
				Key: [][]int{
					{1, 2},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid key 2",
			key: &ciphers.HillKey{
				Key: [][]int{
					{1, 2},
					{},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid key 3 - not invertible",
			key: &ciphers.HillKey{
				Key: [][]int{
					{1, 1},
					{1, 1},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := ciphers.NewHillCipher(tt.key)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("NewHillCipher() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("NewHillCipher() succeeded unexpectedly")
			}

			if !slices.EqualFunc(got.InverseKey().Key, tt.want.Key, slices.Equal) ||
				!slices.EqualFunc(got.Key().Key, tt.key.Key, slices.Equal) {
				t.Errorf("NewHillCipher() key = %v inverse = %v, want key = %v inverse = %v",
					got.Key().Key, got.InverseKey().Key, tt.key.Key, tt.want.Key)
			}
		})
	}
}

func TestGenerateHillKey(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{
			name: "normal 1",
			size: 3,
		},
		{
			name: "normal 2",
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
			name:    "one",
			size:    1,
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
			_, gotErr := ciphers.GenerateHillKey(tt.size)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("GenerateHillKey() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("GenerateHillKey() succeeded unexpectedly")
			}
		})
	}
}

func TestHillCipher_EncryptBlock(t *testing.T) {
	tests := []struct {
		name    string
		key     *ciphers.HillKey
		dst     []byte
		src     []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "normal 1",
			key: &ciphers.HillKey{
				Key: [][]int{
					{25, 5, 18},
					{25, 20, 20},
					{22, 0, 11},
				},
			},
			src:  []byte("Doggiecat"),
			dst:  make([]byte, 9),
			want: []byte("thccaucot"),
		},
		{
			name: "normal 2",
			key: &ciphers.HillKey{
				Key: [][]int{
					{4, 1},
					{13, 25},
				},
			},
			src:  []byte("helloWORLD"),
			dst:  make([]byte, 10),
			want: []byte("gjdcaevjvk"),
		},
		{
			name: "leftover characters 1",
			key: &ciphers.HillKey{
				Key: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
			},
			src:  []byte("my dog LOVES tenniSS"),
			dst:  make([]byte, 20),
			want: []byte("jk ire ikxpe vdrviSS"),
		},
		{
			name: "leftover characters 2",
			key: &ciphers.HillKey{
				Key: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
			},
			src:  []byte("hello world, MUCHACHOO!"),
			dst:  make([]byte, 23),
			want: []byte("qoxbk pbrhd, mvwzlqnzO!"),
		},
		{
			name: "empty dst src",
			key: &ciphers.HillKey{
				Key: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
			},
			src:  []byte{},
			dst:  []byte{},
			want: []byte{},
		},
		{
			name: "dst src size mismatch 1",
			key: &ciphers.HillKey{
				Key: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
			},
			src:     []byte("abc"),
			dst:     make([]byte, 5),
			wantErr: true,
		},
		{
			name: "dst src size mismatch 2",
			key: &ciphers.HillKey{
				Key: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
			},
			src:     []byte("abc"),
			dst:     make([]byte, 1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hc, err := ciphers.NewHillCipher(tt.key)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := hc.EncryptBlock(tt.dst, tt.src)
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
				t.Errorf("Encrypt = %q, want %q", (tt.dst), (tt.want))
			}
		})
	}
}

func TestHillCipher_DecryptBlock(t *testing.T) {
	tests := []struct {
		name    string
		key     *ciphers.HillKey
		dst     []byte
		src     []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "normal 1",
			key: &ciphers.HillKey{
				Key: [][]int{
					{25, 5, 18},
					{25, 20, 20},
					{22, 0, 11},
				},
			},
			src:  []byte("thccaucot"),
			dst:  make([]byte, 9),
			want: []byte("doggiecat"),
		},
		{
			name: "normal 2",
			key: &ciphers.HillKey{
				Key: [][]int{
					{4, 1},
					{13, 25},
				},
			},
			src:  []byte("gjdcaevjvk"),
			dst:  make([]byte, 10),
			want: []byte("helloworld"),
		},
		{
			name: "leftover characters 1",
			key: &ciphers.HillKey{
				Key: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
			},
			src:  []byte("jk ire ikxpe vdrviSS"),
			dst:  make([]byte, 20),
			want: []byte("my dog loves tenniSS"),
		},
		{
			name: "leftover characters 2",
			key: &ciphers.HillKey{
				Key: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
			},
			src:  []byte("qoxbk pbrhd, mvwzlqnzO!"),
			dst:  make([]byte, 23),
			want: []byte("hello world, muchachoO!"),
		},
		{
			name: "empty dst src",
			key: &ciphers.HillKey{
				Key: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
			},
			src:  []byte{},
			dst:  []byte{},
			want: []byte{},
		},
		{
			name: "dst src size mismatch 1",
			key: &ciphers.HillKey{
				Key: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
			},
			src:     []byte("abc"),
			dst:     make([]byte, 5),
			wantErr: true,
		},
		{
			name: "dst src size mismatch 2",
			key: &ciphers.HillKey{
				Key: [][]int{
					{9, 8, 7},
					{6, 13, 14},
					{7, 7, 14},
				},
			},
			src:     []byte("abc"),
			dst:     make([]byte, 1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hc, err := ciphers.NewHillCipher(tt.key)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := hc.DecryptBlock(tt.dst, tt.src)
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
				t.Errorf("Decrypt = %q, want %q", tt.dst, tt.want)
			}
		})
	}
}

func TestHillCipher_RoundTrip(t *testing.T) {
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
			lower := strings.ToLower(tt.message)
			t.Run(tt.name, func(t *testing.T) {
				key, _ := ciphers.GenerateHillKey(tt.size)
				cipher, _ := ciphers.NewHillCipher(key)
				src := []byte(tt.message)
				dst := make([]byte, len(src))

				if err := cipher.EncryptBlock(dst, src); err != nil {
					t.Fatalf("EncryptBlock() failed: %v", err)
				}
				if err := cipher.DecryptBlock(src, dst); err != nil {
					t.Fatalf("DecryptBlock() failed: %v", err)
				}

				if string(src) != lower {
					t.Errorf("Roundtrip = %s, want %s", string(src), lower)
				}
			})
		}
	}
}
