package ciphers_test

import (
	"bytes"
	"testing"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

func TestCaesarEncrypt(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		encrypted string
		key       int
		wantErr   bool
	}{
		{"Normal 1", "Canabis", "Fdqdelv", 3, false},
		{"Normal 2", "Hello World!!", "Mjqqt Btwqi!!", 5, false},
		{"Normal 3", "Chicken", "Ejkemgp", 2, false},
		{"Empty", "", "", 2, false},
		{"Big Key", "Hello World!", "Axeeh Phkew!", 123, false},
		{"Negative Key", "Negative", "Negative", -1, true},
		{"Key of 1", "Positive", "Positive", 0, false},
	}

	for _, testSubject := range tests {
		t.Run(testSubject.name, func(t *testing.T) {
			src := []byte(testSubject.message)
			expected := []byte(testSubject.encrypted)

			cipher, err := ciphers.NewCaesarCipher(testSubject.key)
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

func TestCaesarCipher(t *testing.T) {
	tests := []struct {
		name    string
		message string
		key     int
		wantErr bool
	}{
		{"Normal 1", "Canabis", 3, false},
		{"Normal 2", "Hello World!!", 5, false},
		{"Normal 3", "Chicken", 2, false},
		{"Empty", "", 2, false},
		{"Big Key", "Hello World!", 123, false},
		{"Negative Key", "Negative", -1, true},
		{"Zero Key", "Positive", 0, false},
	}

	for _, testSubject := range tests {
		t.Run(testSubject.name, func(t *testing.T) {
			cipher, err := ciphers.NewCaesarCipher(testSubject.key)
			if (err != nil) != testSubject.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, testSubject.wantErr)
			}
			if err != nil {
				return
			}

			original := []byte(testSubject.message)

			encrypted := make([]byte, len(original))
			decrypted := make([]byte, len(original))

			if err := cipher.EncryptBlock(encrypted, original); err != nil {
				t.Fatal(err)
			}

			if err := cipher.DecryptBlock(decrypted, encrypted); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(decrypted, original) {
				t.Fatalf("Encrypt/Decrypt mismatch\nwant: %s\ngot:  %s", original, decrypted)
			}
		})
	}
}

func FuzzCaesarCipher(f *testing.F) {
	f.Add("Canabis", 3)
	f.Add("ABC", 5)
	f.Add("Hello World!", 2)
	f.Add("", 12)

	f.Fuzz(func(t *testing.T, message string, key int) {
		if key < 0 {
			return
		}

		cipher, err := ciphers.NewCaesarCipher(key)
		if err != nil {
			return
		}

		expected := []byte(message)
		src := make([]byte, len(expected))
		copy(src, expected)

		dst := make([]byte, len(src))

		if err := cipher.EncryptBlock(dst, src); err != nil {
			t.Fatalf("encrypt error: %v", err)
		}

		if err := cipher.DecryptBlock(src, dst); err != nil {
			t.Fatalf("decrypt error: %v", err)
		}

		if !bytes.Equal(src, expected) {
			t.Fatalf("Encrypt/Decrypt mismatch")
		}
	})
}
