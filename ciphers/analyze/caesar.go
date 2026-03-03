package analyze

import (
	"io"
	"os"
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

func (analyzer *CaesarAnalyzer) AnalyzeFile(inputFilepath string) ([]AnalysisResult, error) {
	inFile, err := os.Open(inputFilepath)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()

	buffer := make([]byte, 16*1024) // Read 16KB or less
	n, err := io.ReadFull(inFile, buffer)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	buffer = buffer[:n]

	return analyzer.AnalyzeBuffer(buffer)
}

func (analyzer *CaesarAnalyzer) AnalyzeBuffer(buffer []byte) ([]AnalysisResult, error) {
	var results []AnalysisResult

	dst := make([]byte, len(buffer))
	frequencies := analyzer.model.calculateLetterFrequencies(buffer)

	sortedFrequencies := frequencies
	sort.Slice(sortedFrequencies[:], func(i, j int) bool {
		return sortedFrequencies[i].frequency > sortedFrequencies[j].frequency
	})

	englishMax := byte('e')
	for _, candidate := range sortedFrequencies {
		key := (candidate.letter - englishMax + 26) % 26

		caesarCipher, err := ciphers.NewCaesarCipher(int(key))
		if err != nil {
			return nil, err
		}
		caesarCipher.DecryptBlock(dst, buffer)

		newFrequencies := analyzer.model.calculateLetterFrequencies(dst)
		decryptedScore := analyzer.model.calculateChiSquared(newFrequencies)

		englishScore := analyzer.model.calculateEnglish(dst)

		results = append(results, AnalysisResult{
			Key:          key,
			ChiScore:     decryptedScore,
			EnglishScore: englishScore,
		})

		// if decryptedScore <= chiSquaredThreshold && englishScore >= englishDictionaryThreshold {
		// 	break
		// }
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ChiScore < results[j].ChiScore
	})

	return results, nil
}
