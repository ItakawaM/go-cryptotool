package analyze

import (
	"fmt"
	"sort"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

type CaesarAnalyzer struct {
	model *statisticsModel
}

func NewCaesarAnalyzer() *CaesarAnalyzer {
	return &CaesarAnalyzer{
		model: newStatisticsModel(),
	}
}

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

		caesarCipher, err := ciphers.NewCaesarCipher(int(key))
		if err != nil {
			return nil, err
		}
		caesarCipher.DecryptBlock(dst, buffer)

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
