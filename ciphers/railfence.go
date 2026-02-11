package ciphers

import (
	"os"
)

func reverseString(s string) string {
	reversed := []rune(s)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}

	return string(reversed)
}

// RailFenceEncryptMessage encrypts the given message with the given key
// using the railfence cipher.
// Output: stdout.
func RailFenceEncryptMessage(message string, key int) string {
	if key == 1 {
		return message
	}

	if key >= len(message) {
		return reverseString(message)
	}

	cycle := 2 * (key - 1)
	encrypted := make([]rune, len(message))
	runes := []rune(message)

	index := 0
	// Alternative up-down railfence cipher, rather than the usual down-up
	for level := key - 1; level >= 0; level-- {
		for charIndex := level; charIndex < len(runes); charIndex += cycle {
			encrypted[index] = runes[charIndex]
			index += 1

			// if middle row
			secondCharIndex := charIndex + cycle - 2*level
			if level != key-1 && level != 0 && secondCharIndex < len(message) {
				encrypted[index] = runes[secondCharIndex]
				index += 1
			}
		}
	}

	return string(encrypted)
}

func RailFenceDecryptMessage(encrypted string, key int) string {
	panic("Not Implemented!")
}

// RailFenceEncryptFile encrypts the given file with the given key
// using the railfence cipher.
// Output: file_fenced.
func RailFenceEncryptFile(file string, key int) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	if key == 1 {
		return os.WriteFile(file+"_fenced", data, 0644)
	}

	fileSize := len(data)
	encrypted := make([]byte, 0, fileSize)
	cycle := 2 * (key - 1)

	// Alternative up-down railfence cipher, rather than the usual down-up
	for level := key - 1; level >= 0; level-- {
		for charIndex := level; charIndex < fileSize; charIndex += cycle {
			encrypted = append(encrypted, data[charIndex])

			secondCharIndex := charIndex + cycle - 2*level
			if level != 0 && level != key-1 && secondCharIndex < fileSize {
				encrypted = append(encrypted, data[secondCharIndex])
			}
		}
	}

	return os.WriteFile(file+"_fenced", encrypted, 0644)
}
