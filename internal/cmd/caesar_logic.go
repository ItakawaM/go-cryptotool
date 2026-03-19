package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/ciphers/analyze"
	"github.com/ItakawaM/go-cryptotool/internal/benchmark"
	"github.com/ItakawaM/go-cryptotool/internal/engine"
	"github.com/spf13/cobra"
)

type caesarParams struct {
	key int
	blockCipherParams
}

func caesarPreRunE(command *cobra.Command, params *caesarParams, args []string) error {
	key, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	} else if key < 0 {
		return fmt.Errorf("key can not be negative: %d", key)
	}
	params.key = key

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

func caesarRunE(command *cobra.Command, args []string, params *caesarParams, mode ciphers.CipherMode) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("caesar %s", mode))()
	}

	switch len(args[1:]) {
	case 1:
		message := args[1]

		caesarCipher, caesarErr := ciphers.NewCaesarCipher(params.key)
		if caesarErr != nil {
			return caesarErr
		}

		buffer := []byte(message)

		var err error
		switch mode {
		case ciphers.Encrypt:
			err = caesarCipher.EncryptBlock(buffer, buffer)
		case ciphers.Decrypt:
			err = caesarCipher.DecryptBlock(buffer, buffer)
		}
		if err != nil {
			return err
		}

		command.Println(string(buffer))

	case 2:
		inFilePath := args[1]
		outFilePath := args[2]

		blockSizeBytes := params.blockSize * 1024
		caesarCipher, caesarErr := ciphers.NewCaesarCipher(params.key)
		if caesarErr != nil {
			return caesarErr
		}

		return engine.NewBlockEngine(blockSizeBytes, params.numCPU).ProcessFile(caesarCipher, mode, inFilePath, outFilePath)
	}

	return nil
}

func caesarBruteforcePreRunE(command *cobra.Command, params *caesarParams, args []string) error {
	switch len(args) {
	case 1:
		return params.parseSourceMessageParams(command)
	case 2:
		if !fileExists(args[0]) {
			return fmt.Errorf("provided input file does not exist: %s", args[0])
		}
		return params.parseSourceFileParams()
	default:
		return fmt.Errorf("invalid working mode")
	}
}

func caesarBruteforceRunE(command *cobra.Command, args []string, params *caesarParams) error {
	if isVerbose {
		defer benchmark.MeasurePerformance("caesar bruteforce")()
	}

	switch len(args) {
	case 1:
		message := args[0]

		src := []byte(message)
		dst := bytes.Clone(src)

		for i := range 26 {
			caesarCipher, caesarErr := ciphers.NewCaesarCipher(i)
			if caesarErr != nil {
				return caesarErr
			}

			err := caesarCipher.DecryptBlock(dst, src)
			if err != nil {
				return err
			}

			command.Printf("[%d]: %s\n", i, string(dst))
		}

	case 2:
		inFilePath := args[0]
		outFilePathFolder := fmt.Sprintf("%s_bruteforce", args[1])
		if err := os.MkdirAll(outFilePathFolder, 0755); err != nil {
			return err
		}

		blockSizeBytes := params.blockSize * 1024
		engine := engine.NewBlockEngine(blockSizeBytes, params.numCPU)
		for i := range 26 {
			caesarCipher, caesarErr := ciphers.NewCaesarCipher(i)
			if caesarErr != nil {
				return caesarErr
			}

			if err := engine.ProcessFile(caesarCipher, ciphers.Decrypt,
				inFilePath, filepath.Join(outFilePathFolder, fmt.Sprintf("key_%02d", i))); err != nil {
				return err
			}
		}
	}

	return nil
}

func caesarAnalyzeRunE(command *cobra.Command, args []string) error {
	if isVerbose {
		defer benchmark.MeasurePerformance("caesar analyze")()
	}

	source := args[0]

	var results []analyze.AnalysisResult
	var resultsErr error
	analyzer := analyze.NewCaesarAnalyzer()
	if !fileExists(source) {
		results, resultsErr = analyzer.AnalyzeBuffer([]byte(source))
	} else {
		results, resultsErr = analyzer.AnalyzeFile(source)
	}
	if resultsErr != nil {
		return resultsErr
	}

	for i := range len(results) {
		command.Println(results[i])
	}

	return nil
}
