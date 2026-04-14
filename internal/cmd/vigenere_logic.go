package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/ItakawaM/arcipher/ciphers"
	"github.com/ItakawaM/arcipher/ciphers/analyze"
	"github.com/ItakawaM/arcipher/internal/benchmark"
	"github.com/ItakawaM/arcipher/internal/engine"
	"github.com/spf13/cobra"
)

type vigenereBruteforceParams struct {
	dictionary map[string]struct{}
	blockCipherParams
}

type vigenereFactory struct {
	key     []byte
	autokey bool
}

func (vF *vigenereFactory) name() string {
	if vF.autokey {
		return "vigenere-autokey"
	}

	return "vigenere"
}

func (vF *vigenereFactory) parseKey(keyStr string) error {
	normalizedKey, err := ciphers.NormalizeVigenereKey([]byte(keyStr))
	if err != nil {
		return err
	}
	vF.key = normalizedKey

	return nil
}

func (vF *vigenereFactory) newCipher(_ int) (ciphers.BlockCipher, error) {
	if vF.autokey {
		return ciphers.NewVigenereAutoKeyCipherNormalized(vF.key), nil
	}

	return ciphers.NewVigenereCipherNormalized(vF.key), nil
}

func vigenereBruteforcePreRunE(command *cobra.Command, args []string, params *vigenereBruteforceParams) error {
	if !fileExists(args[0]) {
		return fmt.Errorf("provided dictionary file does not exist: %s", args[0])
	}

	dictionaryFile, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer dictionaryFile.Close()

	rawDictionary, err := io.ReadAll(dictionaryFile)
	if err != nil {
		return err
	}

	dictionary := make(map[string]struct{})
	for word := range strings.FieldsSeq(strings.ToLower(string(rawDictionary))) {
		_, err := ciphers.NormalizeVigenereKey([]byte(word))
		if err != nil {
			continue
		}
		dictionary[word] = struct{}{}
	}
	params.dictionary = dictionary

	switch len(args[1:]) {
	case 1:
		return params.parseSourceMessageParams(command)
	case 2:
		if !fileExists(args[1]) {
			return fmt.Errorf("provided input file does not exist: %s", args[1])
		}
		return params.parseSourceFileParams()
	default:
		return fmt.Errorf("invalid working mode")
	}
}

func vigenereBruteforceRunE(args []string, params *vigenereBruteforceParams, autokey bool) error {
	if isVerbose {
		defer benchmark.MeasurePerformance("vigenere bruteforce")()
	}

	switch len(args[1:]) {
	case 1:
		message := args[1]
		src := []byte(message)
		dst := bytes.Clone(src)

		tab := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tab, "Key\tPlaintext")
		for word := range params.dictionary {
			vigenereVariant := getVigenereVariant(word, autokey)
			if err := vigenereVariant.DecryptBlock(dst, src); err != nil {
				return err
			}

			fmt.Fprintf(tab, "%s\t%s\n", word, string(dst))
		}
		tab.Flush()

	case 2:
		inFilePath, outFilePathFolder := args[1], fmt.Sprintf("%s_bruteforce", args[2])
		if err := os.MkdirAll(outFilePathFolder, 0755); err != nil {
			return err
		}

		blockSizeBytes := params.blockSize * 1024
		blockEngine := engine.NewBlockEngine(blockSizeBytes, params.numCPU)
		for word := range params.dictionary {
			vigenereVariant := getVigenereVariant(word, autokey)
			if err := blockEngine.ProcessFile(vigenereVariant, ciphers.Decrypt,
				inFilePath, filepath.Join(outFilePathFolder, fmt.Sprintf("key_%s", word))); err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("invalid amount of arguments provided")
	}

	return nil
}

func getVigenereVariant(key string, autokey bool) ciphers.BlockCipher {
	var vigenereVariant ciphers.BlockCipher
	if autokey {
		vigenereVariant, _ = ciphers.NewVigenereAutoKeyCipher([]byte(key))
	} else {
		vigenereVariant, _ = ciphers.NewVigenereCipher([]byte(key))
	}

	return vigenereVariant
}

func vigenereAnalyzeRunE(args []string) error {
	if isVerbose {
		defer benchmark.MeasurePerformance("vigenere analyze")()
	}

	source := args[0]

	var results []analyze.VigenereResult
	var err error

	analyzer, _ := analyze.NewVigenereAnalyzer(13) // Lucky number
	if !fileExists(source) {
		results, err = analyzer.AnalyzeBuffer([]byte(source))
	} else {
		results, err = analyze.AnalyzeFile(analyzer, source)
	}
	if err != nil {
		return err
	}

	tab := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tab, "Key\tChi")
	for _, result := range results {
		fmt.Fprintf(tab, "'%s'\t%.4f\n",
			result.Key, result.ChiScore)
	}
	tab.Flush()

	return nil
}
