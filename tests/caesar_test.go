package ciphers_test

import (
	"bytes"
	"testing"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

func TestNewCaesarCipher(t *testing.T) {
	keyTests := []struct {
		name    string
		key     int
		wantErr bool
	}{
		{name: "valid key", key: 15, wantErr: false},
		{name: "invalid key", key: -3, wantErr: true},
	}

	for _, tt := range keyTests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := ciphers.NewCaesarCipher(tt.key)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("NewCaesarCipher() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("NewCaesarCipher() succeeded unexpectedly")
			}
		})
	}

	substitutionTests := []struct {
		name   string
		key    int
		source byte
		want   byte
	}{
		{name: "substitution normal 1", key: 3, source: 'a', want: 'd'},
		{name: "substitution normal 2", key: 1234, source: 'a', want: 'm'},
		{name: "substitution case", key: 3, source: 'B', want: 'E'},
		{name: "substitution no change 1", key: 0, source: 'e', want: 'e'},
		{name: "substitution no change 2", key: 26, source: 'e', want: 'e'},
		{name: "substitution non-alpha 1", key: 23, source: ':', want: ':'},
		{name: "substitution non-alpha 2", key: 23, source: '.', want: '.'},
	}

	for _, tt := range substitutionTests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := ciphers.NewCaesarCipher(tt.key)
			if err != nil {
				t.Fatalf("NewCaesarCipher() failed unexpectedly with key: %d", tt.key)
			}

			got := cipher.SubstitutionTable[tt.source]
			if got != tt.want {
				t.Errorf("Substitution = %v, want %v", got, tt.want)
			}
		})
	}

	reverseTests := []struct {
		name   string
		key    int
		source byte
		want   byte
	}{
		{name: "reverse normal 2", key: 28, source: 'g', want: 'e'},
		{name: "reverse normal 1", key: 20, source: 'A', want: 'G'},
		{name: "reverse no change 1", key: 0, source: 'e', want: 'e'},
		{name: "reverse no change 2", key: 26, source: 'e', want: 'e'},
		{name: "reverse non-alpha 1", key: 1234, source: ':', want: ':'},
		{name: "reverse non-alpha 2", key: 1234, source: ' ', want: ' '},
	}

	for _, tt := range reverseTests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := ciphers.NewCaesarCipher(tt.key)
			if err != nil {
				t.Fatalf("NewCaesarCipher() failed unexpectedly with key: %d", tt.key)
			}

			got := cipher.ReverseTable[tt.source]
			if got != tt.want {
				t.Errorf("Reverse = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("roundtrip", func(t *testing.T) {
		cipher, err := ciphers.NewCaesarCipher(3)
		if err != nil {
			t.Fatalf("NewCaesarCipher() failed unexpectedly with key: %d", 3)
		}

		for i := range 256 {
			encrypted := cipher.SubstitutionTable[i]
			if cipher.ReverseTable[encrypted] != byte(i) {
				t.Errorf("roundtrip failed for byte %d", i)
			}
		}
	})
}

func TestCaesarCipher_EncryptBlock(t *testing.T) {
	tests := []struct {
		name    string
		key     int
		src     []byte
		dst     []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "lowercase 1",
			key:  3,
			src:  []byte("abc"),
			dst:  make([]byte, 3),
			want: []byte("def"),
		},
		{
			name: "lowercase 2",
			key:  3,
			src:  []byte("xyz"),
			dst:  make([]byte, 3),
			want: []byte("abc"),
		},
		{
			name: "uppercase 1",
			key:  3,
			src:  []byte("ABC"),
			dst:  make([]byte, 3),
			want: []byte("DEF"),
		},
		{
			name: "uppercase 2",
			key:  3,
			src:  []byte("XYZ"),
			dst:  make([]byte, 3),
			want: []byte("ABC"),
		},
		{
			name: "non-alpha",
			key:  3,
			src:  []byte("a.b c"),
			dst:  make([]byte, 5),
			want: []byte("d.e f"),
		},
		{
			name: "no change 1",
			key:  0,
			src:  []byte("abc"),
			dst:  make([]byte, 3),
			want: []byte("abc"),
		},
		{
			name: "no change 2",
			key:  26,
			src:  []byte("abc"),
			dst:  make([]byte, 3),
			want: []byte("abc"),
		},
		{
			name: "empty dst src",
			key:  13,
			src:  []byte{},
			dst:  []byte{},
			want: []byte{},
		},
		{
			name:    "dst src size mismatch 1",
			key:     13,
			src:     []byte("abc"),
			dst:     make([]byte, 5),
			wantErr: true,
		},
		{
			name:    "dst src size mismatch 2",
			key:     10,
			src:     []byte("abc"),
			dst:     make([]byte, 1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc, err := ciphers.NewCaesarCipher(tt.key)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := cc.EncryptBlock(tt.dst, tt.src)
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

func TestCaesarCipher_DecryptBlock(t *testing.T) {
	tests := []struct {
		name    string
		key     int
		src     []byte
		dst     []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "lowercase 1",
			key:  5,
			src:  []byte("fgh"),
			dst:  make([]byte, 3),
			want: []byte("abc"),
		},
		{
			name: "lowercase 2",
			key:  23,
			src:  []byte("xyz"),
			dst:  make([]byte, 3),
			want: []byte("abc"),
		},
		{
			name: "uppercase 1",
			key:  5,
			src:  []byte("FGH"),
			dst:  make([]byte, 3),
			want: []byte("ABC"),
		},
		{
			name: "uppercase 2",
			key:  23,
			src:  []byte("XYZ"),
			dst:  make([]byte, 3),
			want: []byte("ABC"),
		},
		{
			name: "non-alpha",
			key:  5,
			src:  []byte("f.g h"),
			dst:  make([]byte, 5),
			want: []byte("a.b c"),
		},
		{
			name: "no change 1",
			key:  0,
			src:  []byte("abc"),
			dst:  make([]byte, 3),
			want: []byte("abc"),
		},
		{
			name: "no change 2",
			key:  26,
			src:  []byte("abc"),
			dst:  make([]byte, 3),
			want: []byte("abc"),
		},
		{
			name: "empty dst src",
			key:  13,
			src:  []byte{},
			dst:  []byte{},
			want: []byte{},
		},
		{
			name:    "dst src size mismatch 1",
			key:     13,
			src:     []byte("abc"),
			dst:     make([]byte, 5),
			wantErr: true,
		},
		{
			name:    "dst src size mismatch 2",
			key:     10,
			src:     []byte("abc"),
			dst:     make([]byte, 1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc, err := ciphers.NewCaesarCipher(tt.key)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := cc.DecryptBlock(tt.dst, tt.src)
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

func TestCaesarCipher_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		message string
		key     int
	}{
		{name: "normal 1", message: "Hello World", key: 5},
		{name: "normal 2", message: "Goodbye Crypto", key: 1234},
		{name: "normal 3", message: "We Love Kitties", key: 1},
		{name: "non-alpha", message: "123!!@@%^^ !", key: 1},
		{name: "no change 1", message: "We Love Kitties", key: 0},
		{name: "no change 2", message: "We Love Kitties", key: 26},
		{name: "empty", message: "", key: 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, _ := ciphers.NewCaesarCipher(tt.key)
			src := []byte(tt.message)
			dst := make([]byte, len(src))

			if err := cipher.EncryptBlock(dst, src); err != nil {
				t.Fatalf("EncryptBlock() failed: %v", err)
			}
			if err := cipher.DecryptBlock(src, dst); err != nil {
				t.Fatalf("DecryptBlock() failed: %v", err)
			}

			if string(src) != tt.message {
				t.Errorf("Roundtrip = %s, want %s", string(src), tt.message)
			}
		})
	}
}
