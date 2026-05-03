package ciphers_test

import (
	"bytes"
	"testing"

	"github.com/ItakawaM/arcipher/ciphers"
)

func TestVigenereAutoKeyCipher_EncryptBlock(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		src     []byte
		dst     []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "normal 1",
			key:  []byte("cryptography"),
			src:  []byte("Hello World!"),
			dst:  make([]byte, 12),
			want: []byte("Jvjah Kuils!"),
		},
		{
			name: "normal 2",
			key:  []byte("cat"),
			src:  []byte("Dune"),
			dst:  make([]byte, 4),
			want: []byte("Fugh"),
		},
		{
			name: "normal 3",
			key:  []byte("cat"),
			src:  []byte("Do"),
			dst:  make([]byte, 2),
			want: []byte("Fo"),
		},
		{
			name: "normal 4",
			key:  []byte("cipher"),
			src:  []byte("Here is the calculator, which transforms entered text (encrypt or decrypt) using Vigenere cipher. The algorithm is quite simple."),
			dst:  make([]byte, 128),
			want: []byte("Jmgl mj alv gidvbpctzt, qsivv knhvumhimf wshvdwh gxbk (iqvvvix bt ucrkmgw) yuzlv Ocymakmm imclvv. Vpt hpxhymtss wj ynpfm kygxei."),
		},
		{
			name: "non-alpha",
			key:  []byte("cat"),
			src:  []byte("123456Hello789!@:"),
			dst:  make([]byte, 17),
			want: []byte("123456Jeess789!@:"),
		},
		{
			name: "empty",
			key:  []byte("cat"),
			src:  []byte{},
			dst:  []byte{},
			want: []byte{},
		},
		{
			name:    "dst src size mismatch 1",
			key:     []byte("cat"),
			src:     []byte("Hello World!"),
			dst:     make([]byte, 4),
			wantErr: true,
		},
		{
			name:    "dst src size mismatch 2",
			key:     []byte("cat"),
			src:     []byte("Hello World!"),
			dst:     make([]byte, 254),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := ciphers.NewVigenereAutoKeyCipher(&ciphers.VigenereKey{
				Key: tt.key,
			})
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := cipher.EncryptBlock(tt.dst, tt.src)
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

func TestVigenereAutoKeyCipher_DecryptBlock(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		src     []byte
		dst     []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "normal 1",
			key:  []byte("cryptography"),
			src:  []byte("Jvjah Otkoc!"),
			dst:  make([]byte, 12),
			want: []byte("Hello Anton!"),
		},
		{
			name: "normal 2",
			key:  []byte("cat"),
			src:  []byte("Yokhr"),
			dst:  make([]byte, 5),
			want: []byte("World"),
		},
		{
			name: "normal 3",
			key:  []byte("cat"),
			src:  []byte("Fo"),
			dst:  make([]byte, 2),
			want: []byte("Do"),
		},
		{
			name: "normal 4",
			key:  []byte("cipher"),
			src:  []byte("Jmgl mj alv gidvbpctzt, qsivv knhvumhimf wshvdwh gxbk (iqvvvix bt ucrkmgw) yuzlv Ocymakmm imclvv. Vpt hpxhymtss wj ynpfm kygxei."),
			dst:  make([]byte, 128),
			want: []byte("Here is the calculator, which transforms entered text (encrypt or decrypt) using Vigenere cipher. The algorithm is quite simple."),
		},
		{
			name: "non-alpha",
			key:  []byte("cat"),
			src:  []byte("123456Jeess789!@:"),
			dst:  make([]byte, 17),
			want: []byte("123456Hello789!@:"),
		},
		{
			name: "empty",
			key:  []byte("cat"),
			src:  []byte{},
			dst:  []byte{},
			want: []byte{},
		},
		{
			name:    "dst src size mismatch 1",
			key:     []byte("cat"),
			src:     []byte("Hello World!"),
			dst:     make([]byte, 4),
			wantErr: true,
		},
		{
			name:    "dst src size mismatch 2",
			key:     []byte("cat"),
			src:     []byte("Hello World!"),
			dst:     make([]byte, 254),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := ciphers.NewVigenereAutoKeyCipher(&ciphers.VigenereKey{
				Key: tt.key,
			})
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}

			gotErr := cipher.DecryptBlock(tt.dst, tt.src)
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

func TestVigenereAutoKeyCipher_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		message string
		key     []byte
	}{
		{
			name:    "normal 1",
			message: "Hello World",
			key:     []byte("hello"),
		},
		{
			name:    "normal 2",
			message: "Goodbye Crypto",
			key:     []byte("dog"),
		},
		{
			name:    "normal 3",
			message: "We Love Kitties",
			key:     []byte("cat"),
		},
		{
			name:    "normal 4",
			message: "cat",
			key:     []byte("WeLoveKitties"),
		},
		{
			name:    "non-alpha",
			message: "1Hello23!!@@%^^ !",
			key:     []byte("meow"),
		},
		{
			name:    "single",
			message: "a",
			key:     []byte("b"),
		},
		{
			name:    "empty",
			message: "",
			key:     []byte("hello"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, _ := ciphers.NewVigenereAutoKeyCipher(&ciphers.VigenereKey{
				Key: tt.key,
			})
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
