package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"text/tabwriter"

	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/ciphers/analyze"
	"github.com/ItakawaM/go-cryptotool/internal/benchmark"
	"github.com/ItakawaM/go-cryptotool/internal/engine"
	"github.com/spf13/cobra"
)

type caesarFactory struct {
	key int
}

func (cF *caesarFactory) name() string {
	return "caesar"
}

func (cF *caesarFactory) parseKey(keyStr string) error {
	key, err := strconv.Atoi(keyStr)
	if err != nil {
		return err
	} else if key < 0 {
		return fmt.Errorf("key can not be negative: %d", key)
	}
	cF.key = key

	return nil
}

func (cF *caesarFactory) newCipher(_ int) (ciphers.BlockCipher, error) {
	return ciphers.NewCaesarCipher(cF.key)
}

func caesarBruteforcePreRunE(command *cobra.Command, params *blockCipherParams, args []string) error {
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

func caesarBruteforceRunE(args []string, params *blockCipherParams) error {
	if isVerbose {
		defer benchmark.MeasurePerformance("caesar bruteforce")()
	}

	switch len(args) {
	case 1:
		message := args[0]

		src := []byte(message)
		dst := bytes.Clone(src)

		tab := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tab, "Key\tPlaintext")
		for i := range 26 {
			caesarCipher, err := ciphers.NewCaesarCipher(i)
			if err != nil {
				return err
			}

			err = caesarCipher.DecryptBlock(dst, src)
			if err != nil {
				return err
			}

			fmt.Fprintf(tab, "%02d\t%s\n", i, string(dst))
		}
		tab.Flush()

	case 2:
		inFilePath, outFilePathFolder := args[0], fmt.Sprintf("%s_bruteforce", args[1])
		if err := os.MkdirAll(outFilePathFolder, 0755); err != nil {
			return err
		}

		blockSizeBytes := params.blockSize * 1024
		blockEngine := engine.NewBlockEngine(blockSizeBytes, params.numCPU)
		for i := range 26 {
			caesarCipher, err := ciphers.NewCaesarCipher(i)
			if err != nil {
				return err
			}

			if err = blockEngine.ProcessFile(caesarCipher, ciphers.Decrypt,
				inFilePath, filepath.Join(outFilePathFolder, fmt.Sprintf("key_%02d", i))); err != nil {
				return err
			}
		}
	}

	return nil
}

func caesarAnalyzeRunE(args []string) error {
	if isVerbose {
		defer benchmark.MeasurePerformance("caesar analyze")()
	}

	source := args[0]

	var results []analyze.AnalysisResult
	var err error

	analyzer := analyze.NewCaesarAnalyzer()
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
		fmt.Fprintf(tab, "%02d\t%.3f\n",
			result.Key, result.ChiScore)
	}
	tab.Flush()

	return nil
}
