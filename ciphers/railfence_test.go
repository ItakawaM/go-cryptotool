package ciphers

import (
	"bytes"
	"testing"
)

func TestRailFenceEncrypt(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		encrypted string
		key       int
	}{
		{"Normal 1", "Canabis", "nsaaiCb", 3},
		{"Normal 2", "Hello World!!", "o!l !lWdeolHr", 5},
		{"Normal 3", "Chicken", "hceCikn", 2},
		{"Empty", "", "", 2},
		{"Big Key", "Hello World!", "!dlroW olleH", 123},
		{"Negative Key", "Negative", "Negative", -1},
		{"Key of 1", "Positive", "Positive", 1},
	}

	for _, testSubject := range tests {
		t.Run(testSubject.name, func(t *testing.T) {
			cipher := NewRailFenceCipher(testSubject.key)

			got := []byte(testSubject.message)
			want := []byte(testSubject.encrypted)

			buffer := make([]byte, len(got))

			if err := cipher.EncryptBlock(got, buffer); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, want) {
				t.Fatalf("want: %s\ngot: %s", want, got)
			}
		})
	}
}

func TestRailFenceCipher(t *testing.T) {
	tests := []struct {
		name    string
		message string
		key     int
	}{
		{"Normal 1", "Canabis", 3},
		{"Normal 2", "Hello World!", 5},
		{"Empty", "", 2},
		{"Big Key", "Hello World!", 123},
		{"Negative Key", "Negative", -1},
		{"Key of 1", "Positive", 1},
	}

	for _, testSubject := range tests {
		t.Run(testSubject.name, func(t *testing.T) {
			cipher := NewRailFenceCipher(testSubject.key)

			want := []byte(testSubject.message)
			got := make([]byte, len(want))
			copy(got, want)

			buffer := make([]byte, len(want))

			if err := cipher.EncryptBlock(got, buffer); err != nil {
				t.Fatal(err)
			}

			if err := cipher.DecryptBlock(got, buffer); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, want) {
				t.Fatalf("want: %s, got: %s", want, got)
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
			key = len(message)
		}

		cipher := NewRailFenceCipher(key)

		want := []byte(message)
		got := make([]byte, len(want))
		copy(got, want)

		buffer := make([]byte, len(got))

		cipher.EncryptBlock(got, buffer)
		cipher.DecryptBlock(got, buffer)

		if !bytes.Equal(got, want) {
			t.Fatalf("Encrypt/Decrypt mismatch")
		}
	})
}
