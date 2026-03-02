package analyze

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

var englishFrequencies = [26]float64{
	8.167,  // A
	1.492,  // B
	2.782,  // C
	4.253,  // D
	12.702, // E
	2.228,  // F
	2.015,  // G
	6.094,  // H
	6.966,  // I
	0.153,  // J
	0.772,  // K
	4.025,  // L
	2.406,  // M
	6.749,  // N
	7.507,  // O
	1.929,  // P
	0.095,  // Q
	5.987,  // R
	6.327,  // S
	9.056,  // T
	2.758,  // U
	0.978,  // V
	2.360,  // W
	0.150,  // X
	1.974,  // Y
	0.074,  // Z
}

type AnalysisResult struct {
	Key   byte
	Score float64
}

func (ar AnalysisResult) String() string {
	return fmt.Sprintf("[%02d]: %.3f", ar.Key, ar.Score)
}

func AnalyzeCaesarFile(inputFilepath string) ([]AnalysisResult, error) {
	inFile, err := os.Open(inputFilepath)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()

	buffer := make([]byte, 16*1204) // Read 16KB or less
	n, err := io.ReadFull(inFile, buffer)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	buffer = buffer[:n]

	return AnalyzeCaesarBuffer(buffer)
}

func AnalyzeCaesarBuffer(buffer []byte) ([]AnalysisResult, error) {
	var results []AnalysisResult

	dst := make([]byte, len(buffer))
	for key := range 26 {
		caesarCipher, err := ciphers.NewCaesarCipher(key)
		if err != nil {
			return nil, err
		}

		if err := caesarCipher.DecryptBlock(dst, buffer); err != nil {
			return nil, err
		}

		frequencies := letterFrequency(dst)
		score := chiSquared(frequencies)

		results = append(results, AnalysisResult{
			Key:   byte(key),
			Score: score,
		},
		)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score < results[j].Score
	})

	return results, nil
}

func letterFrequency(buffer []byte) [26]float64 {
	var frequencies [26]float64
	var total float64

	for _, char := range buffer {
		if char >= 'a' && char <= 'z' {
			frequencies[char-'a']++
			total++
		} else if char >= 'A' && char <= 'Z' {
			frequencies[char-'A']++
			total++
		}
	}

	if total == 0 {
		return frequencies
	}

	for i := range frequencies {
		frequencies[i] = (frequencies[i] / total) * 100
	}

	return frequencies
}

func chiSquared(frequencies [26]float64) float64 {
	score := 0.0

	for i := range 26 {
		expected := englishFrequencies[i]
		difference := frequencies[i] - expected
		score += (difference * difference) / expected
	}

	return score
}
