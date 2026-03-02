package ciphers_test

import (
	"bytes"
	"testing"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

func TestRailFenceEncrypt(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		encrypted string
		key       int
		wantErr   bool
	}{
		{"Normal 1", "Canabis", "nsaaiCb", 3, false},
		{"Normal 2", "Hello World!!", "o!l !lWdeolHr", 5, false},
		{"Normal 3", "Chicken", "hceCikn", 2, false},
		{"Empty", "", "", 2, false},
		{"Big Key", "Hello World!", "!dlroW olleH", 123, false},
		{"Negative Key", "Negative", "Negative", -1, true},
		{"Key of 1", "Positive", "Positive", 1, false},
	}

	for _, testSubject := range tests {
		t.Run(testSubject.name, func(t *testing.T) {
			src := []byte(testSubject.message)
			expected := []byte(testSubject.encrypted)

			cipher, err := ciphers.NewRailFenceCipher(testSubject.key, len(src))
			if (err != nil) != testSubject.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, testSubject.wantErr)
			}
			if err != nil {
				return
			}

			dst := make([]byte, len(src))

			if err := cipher.EncryptBlock(dst, src); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(dst, expected) {
				t.Fatalf("want: %s\ngot: %s", expected, dst)
			}
		})
	}
}

func TestRailFenceCipher(t *testing.T) {
	tests := []struct {
		name    string
		message string
		key     int
		wantErr bool
	}{
		{"Normal 1", "Canabis", 3, false},
		{"Normal 2", "Hello World!", 5, false},
		{"Empty", "", 2, false},
		{"Big Key", "Hello World!", 123, false},
		{"Negative Key", "Negative", -1, true},
		{"Key of 1", "Positive", 1, false},
	}

	for _, testSubject := range tests {
		t.Run(testSubject.name, func(t *testing.T) {
			cipher, err := ciphers.NewRailFenceCipher(testSubject.key, len(testSubject.message))
			if (err != nil) != testSubject.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, testSubject.wantErr)
			}
			if err != nil {
				return
			}
			expected := []byte(testSubject.message)
			src := make([]byte, len(expected))
			copy(src, expected)

			dst := make([]byte, len(src))

			if err := cipher.EncryptBlock(dst, src); err != nil {
				t.Fatal(err)
			}

			if err := cipher.DecryptBlock(src, dst); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(src, expected) {
				t.Fatalf("want: %s, got: %s", expected, src)
			}
		})
	}
}

func FuzzRailFenceCipher(f *testing.F) {
	f.Add("Canabis", 3)
	f.Add("ABC", 5)
	f.Add("Hello World!", 2)
	f.Add("", 12)

	f.Fuzz(func(t *testing.T, message string, key int) {
		if key <= 1 {
			return
		} else if key > len(message)+10 {
			key = len(message) + 1
		}

		cipher, err := ciphers.NewRailFenceCipher(key, len(message))
		if err != nil {
			t.Fatalf("%s", err)
		}

		expected := []byte(message)
		src := make([]byte, len(expected))
		copy(src, expected)

		dst := make([]byte, len(src))

		cipher.EncryptBlock(dst, src)
		cipher.DecryptBlock(src, dst)

		if !bytes.Equal(src, expected) {
			t.Fatalf("Encrypt/Decrypt mismatch")
		}
	})
}
