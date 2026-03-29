package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/internal/benchmark"
	"github.com/ItakawaM/go-cryptotool/internal/engine"
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

func vigenereBruteforceRunE(command *cobra.Command, args []string, params *vigenereBruteforceParams, autokey bool) error {
	if isVerbose {
		defer benchmark.MeasurePerformance("vigenere bruteforce")()
	}

	switch len(args[1:]) {
	case 1:
		message := args[1]
		src := []byte(message)
		dst := bytes.Clone(src)

		for word := range params.dictionary {
			vigenereVariant := getVigenereVariant(word, autokey)
			if err := vigenereVariant.DecryptBlock(dst, src); err != nil {
				return err
			}

			command.Printf("[%s]: '%s'\n", word, string(dst))
		}

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
