package analyze

import (
	_ "embed"
	"strings"
)

const (
	chiSquaredThreshold        float64 = 200.0
	englishDictionaryThreshold float64 = 0.5
)

type letterFrequency struct {
	letter    byte
	frequency float64
}

//go:embed english_words.txt
var englishWordsFile []byte

type statisticsModel struct {
	englishWordsDictionary   map[string]struct{}
	englishLetterFrequencies [26]letterFrequency
}

func newStatisticsModel() *statisticsModel {
	dictionary := make(map[string]struct{})
	for word := range strings.FieldsSeq(strings.ToLower(string(englishWordsFile))) {
		dictionary[word] = struct{}{}
	}

	var englishFrequencies = [26]letterFrequency{
		{'a', 8.167},
		{'b', 1.492},
		{'c', 2.782},
		{'d', 4.253},
		{'e', 12.702},
		{'f', 2.228},
		{'g', 2.015},
		{'h', 6.094},
		{'i', 6.966},
		{'j', 0.153},
		{'k', 0.772},
		{'l', 4.025},
		{'m', 2.406},
		{'n', 6.749},
		{'o', 7.507},
		{'p', 1.929},
		{'q', 0.095},
		{'r', 5.987},
		{'s', 6.327},
		{'t', 9.056},
		{'u', 2.758},
		{'v', 0.978},
		{'w', 2.360},
		{'x', 0.150},
		{'y', 1.974},
		{'z', 0.074},
	}

	return &statisticsModel{
		englishWordsDictionary:   dictionary,
		englishLetterFrequencies: englishFrequencies,
	}
}

func (model *statisticsModel) calculateLetterFrequencies(buffer []byte) [26]letterFrequency {
	var frequencies [26]letterFrequency
	for i := range 26 {
		frequencies[i].letter = byte('a' + i)
	}

	total := 0.0
	for _, char := range buffer {
		if char >= 'a' && char <= 'z' {
			frequencies[char-'a'].frequency++
			total++
		} else if char >= 'A' && char <= 'Z' {
			frequencies[char-'A'].frequency++
			total++
		}
	}

	if total == 0 {
		return frequencies
	}

	for i := range frequencies {
		frequencies[i].frequency = (frequencies[i].frequency / total) * 100
	}

	return frequencies
}

func (model *statisticsModel) calculateChiSquared(frequencies [26]letterFrequency) float64 {
	score := 0.0
	for i := range 26 {
		expected := model.englishLetterFrequencies[i].frequency
		difference := frequencies[i].frequency - expected
		score += (difference * difference) / expected
	}

	return score
}

func (model *statisticsModel) calculateEnglish(buffer []byte) float64 {
	words := strings.Fields(strings.ToLower(string(buffer)))
	if len(words) == 0 {
		return 0
	}

	matches := 0
	for _, word := range words {
		word = strings.Trim(word, ".,!?;:\"'()-")
		if _, ok := model.englishWordsDictionary[word]; ok {
			matches += 1
		}
	}

	return float64(matches) / float64(len(words))
}
