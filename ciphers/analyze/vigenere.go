package analyze

import (
	"fmt"
	"math"
	"sort"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

/*
VigenereAnalyzer performs statistical analysis to crack Vigenère cipher encrypted text.

It uses n-gram frequency analysis and Kasiski examination to determine the key length,
then applies Caesar cipher analysis to each character position to recover the key.
*/
type VigenereAnalyzer struct {
	shiftAnalyzer *CaesarAnalyzer
	nGramTree     *tree
}

/*
NewVigenereAnalyzer creates a new VigenereAnalyzer instance.

The maxNgramLength parameter specifies the maximum n-gram length to use for analysis.
*/
func NewVigenereAnalyzer(maxNgramLength int) *VigenereAnalyzer {
	return &VigenereAnalyzer{
		shiftAnalyzer: NewCaesarAnalyzer(),
		nGramTree:     newTree(maxNgramLength),
	}
}

/*
AnalyzeBuffer analyzes the given buffer to find the most likely Vigenère cipher key.

It returns a slice of VigenereResult sorted by chi-squared score (best match first).

The maximum number of results returned is 10.
*/
func (analyzer *VigenereAnalyzer) AnalyzeBuffer(buffer []byte) ([]VigenereResult, error) {
	if len(buffer) == 0 {
		return nil, fmt.Errorf("buffer cannot be empty")
	}
	analyzer.nGramTree = newTree(analyzer.nGramTree.maxHeight)

	cleanedBuffer := cleanBuffer(buffer)
	textLength := len(cleanedBuffer)

	analyzer.nGramTree.insertAllNgrams(normalizeBuffer(cleanedBuffer))
	possibleKeyLengths := analyzer.calculateKeyLength()
	possibleKeyLengths = possibleKeyLengths[:min(10, len(possibleKeyLengths))]

	results := make([]VigenereResult, min(10, len(possibleKeyLengths)))
	dst := make([]byte, textLength)

	for candidateIndex := range possibleKeyLengths {
		candidate := possibleKeyLengths[candidateIndex].number
		shiftBuffers := make([][]byte, candidate)
		for i := range shiftBuffers {
			shiftBuffers[i] = make([]byte, 0, int(math.Ceil(float64(textLength)/float64(candidate))))
		}

		possibleKey := make([]byte, candidate)
		for i := range candidate {
			for j := i; j < textLength; j += candidate {
				shiftBuffers[i] = append(shiftBuffers[i], cleanedBuffer[j])
			}

			shiftResults, err := analyzer.shiftAnalyzer.AnalyzeBuffer(shiftBuffers[i])
			if err != nil {
				return nil, err
			}

			possibleKey[i] = (shiftResults[0].Key + 'a')
		}

		cipher, err := ciphers.NewVigenereCipher(possibleKey)
		if err != nil {
			return nil, err
		}

		if err := cipher.DecryptBlock(dst, cleanedBuffer); err != nil {
			return nil, err
		}

		chiScore := analyzer.shiftAnalyzer.model.calculateChiSquared(calculateLetterFrequencies(dst, true))
		results[candidateIndex] = VigenereResult{
			Key:      possibleKey,
			ChiScore: chiScore,
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ChiScore < results[j].ChiScore
	})

	return results, nil
}

type factor struct {
	number int
	count  int
}

func (analyzer *VigenereAnalyzer) calculateKeyLength() []factor {
	distances := make([]int, 0)
	for _, ngram := range analyzer.nGramTree.collectNgrams() {
		for i := range len(ngram.positions) - 1 {
			distances = append(distances, ngram.positions[i+1]-ngram.positions[i])
		}
	}

	factors := make(map[int]int)
	for _, distance := range distances {
		for i := 2; i < int(math.Sqrt(float64(distance)))+1; i++ {
			if distance%i == 0 {
				factors[i] += 1
				if i*i != distance {
					factors[distance/i] += 1
				}
			}
		}
	}

	results := make([]factor, 0, len(factors))
	for key, value := range factors {
		results = append(results, factor{key, value})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].count > results[j].count
	})

	return results
}
