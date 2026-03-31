package analyze

import (
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

func (analyzer *CaesarAnalyzer) AnalyzeBuffer(buffer []byte) ([]AnalysisResult, error) {
	var results []AnalysisResult

	dst := make([]byte, len(buffer))

	frequencies := analyzer.model.calculateLetterFrequencies(buffer)
	sort.Slice(frequencies[:], func(i, j int) bool {
		return frequencies[i].frequency > frequencies[j].frequency
	})

	englishMax := byte('e')
	for _, candidate := range frequencies {
		key := (candidate.letter - englishMax + 26) % 26

		caesarCipher, err := ciphers.NewCaesarCipher(int(key))
		if err != nil {
			return nil, err
		}
		caesarCipher.DecryptBlock(dst, buffer)

		newFrequencies := analyzer.model.calculateLetterFrequencies(dst)
		decryptedScore := analyzer.model.calculateChiSquared(newFrequencies)

		results = append(results, AnalysisResult{
			Key:      key,
			ChiScore: decryptedScore,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ChiScore < results[j].ChiScore
	})

	return results, nil
}
