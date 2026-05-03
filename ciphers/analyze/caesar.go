package analyze

import (
	"fmt"
	"sort"

	"github.com/ItakawaM/arcipher/ciphers"
)

/*
CaesarAnalyzer performs statistical analysis to crack Caesar cipher encrypted text.

It uses chi-squared frequency analysis to determine the most likely key.
*/
type CaesarAnalyzer struct {
	model *statisticsModel
}

/*
NewCaesarAnalyzer creates a new CaesarAnalyzer instance.
*/
func NewCaesarAnalyzer() *CaesarAnalyzer {
	return &CaesarAnalyzer{
		model: newStatisticsModel(),
	}
}

/*
AnalyzeBuffer analyzes the given buffer to find the most likely Caesar cipher key.

It returns a slice of CaesarResult sorted by chi-squared score (best match first).
*/
func (analyzer *CaesarAnalyzer) AnalyzeBuffer(buffer []byte) ([]CaesarResult, error) {
	if len(buffer) == 0 {
		return nil, fmt.Errorf("buffer cannot be empty")
	}

	results := make([]CaesarResult, 26)
	dst := make([]byte, len(buffer))

	frequencies := calculateLetterFrequencies(buffer, true)
	sort.Slice(frequencies[:], func(i, j int) bool {
		return frequencies[i].frequency > frequencies[j].frequency
	})

	englishMax := byte('e')
	for i, candidate := range frequencies {
		key := (candidate.letter - englishMax + 26) % 26

		caesarCipher := ciphers.NewCaesarCipher(&ciphers.CaesarKey{
			Key: int(key),
		})
		if err := caesarCipher.DecryptBlock(dst, buffer); err != nil {
			return nil, err
		}

		newFrequencies := calculateLetterFrequencies(dst, true)
		decryptedScore := analyzer.model.calculateChiSquared(newFrequencies)

		results[i] = CaesarResult{
			Key:      key,
			ChiScore: decryptedScore,
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ChiScore < results[j].ChiScore
	})

	return results, nil
}
