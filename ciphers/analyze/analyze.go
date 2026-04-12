// Package analyze provides functionality for cryptanalysis of classical ciphers.
package analyze

import (
	"io"
	"os"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

/*
Analyzer defines the interface for cipher analysis implementations.
*/
type Analyzer[T []CaesarResult | []VigenereResult] interface {
	/*
		AnalyzeBuffer analyzes the given byte buffer and returns a slice of results
		containing the detected key(s) and their corresponding chi-squared scores.
	*/
	AnalyzeBuffer(buffer []byte) (T, error)
}

/*
CaesarResult holds the analysis result for Caesar cipher,
containing the detected key and its chi-squared score.
*/
type CaesarResult struct {
	Key      byte
	ChiScore float64
}

/*
VigenereResult holds the analysis result for Vigenère cipher,
containing the detected key and its chi-squared score.
*/
type VigenereResult struct {
	Key      []byte
	ChiScore float64
}

/*
AnalyzeFile reads a file and analyzes its contents using the provided analyzer.

It reads up to 16KB of data from the file and returns the analysis results.
*/
func AnalyzeFile[T []CaesarResult | []VigenereResult](analyzer Analyzer[T], inputFilepath string) (T, error) {
	var zero T
	inFile, err := os.Open(inputFilepath)
	if err != nil {
		return zero, err
	}
	defer inFile.Close()

	buffer := make([]byte, 16*1024) // Read 16KB or less
	n, err := io.ReadFull(inFile, buffer)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return zero, err
	}
	buffer = buffer[:n]

	return analyzer.AnalyzeBuffer(buffer)
}

func cleanBuffer(buffer []byte) []byte {
	clean := make([]byte, len(buffer))
	n := 0
	for _, char := range buffer {
		switch {
		case char >= 'a' && char <= 'z':
			clean[n] = char
			n += 1

		case char >= 'A' && char <= 'Z':
			clean[n] = char - 'A' + 'a'
			n += 1
		}
	}

	return clean[:n]
}

func normalizeBuffer(buffer []byte) []byte {
	normalized := make([]byte, len(buffer))
	for index, char := range buffer {
		normalized[index] = ciphers.GetShift(char)
	}

	return normalized
}
