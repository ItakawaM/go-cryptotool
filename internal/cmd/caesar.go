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

type CaesarParams struct {
	key int
	BlockCipherParams
}

func NewCaesarCommand() *cobra.Command {
	caesarCmd := &cobra.Command{
		Use:   "caesar",
		Short: "Encrypt or decrypt data using the Caesar cipher",
		Long: `The Caesar cipher is a classical substitution cipher that shifts
each letter in the plaintext by a fixed number of positions
down the alphabet.

For example, with a shift of 3, A becomes D, B becomes E, and so on.
After reaching Z, the cipher wraps around to the beginning
of the alphabet.

This command allows encryption and decryption of messages or files
using a specified shift value (key).
`,
	}
	caesarCmd.AddCommand(
		newCaesarEncryptCommand(),
		newCaesarDecryptCommand(),
		newCaesarBruteforceCommand(),
		newCaesarAnalyzeCommand(),
	)

	return caesarCmd
}

func newCaesarEncryptCommand() *cobra.Command {
	params := &CaesarParams{}

	encryptCmd := &cobra.Command{
		Use:   "encrypt <key> <message | input> [output]",
		Short: "Encrypt a given message/file with a shift key",
		Args:  cobra.RangeArgs(2, 3),
		Long: `This command allows encryption of messages or files
using a specified shift value (key).

Each letter in the input is shifted forward in the alphabet
by the specified number. The alphabet wraps around after Z.
Non-alphabetic characters remain unchanged.

A shift of 0 results in no transformation.

Examples:

  Encrypt text:
    1. cipher caesar encrypt 3 "AttackAtDawn"

  Encrypt a file:
    1. cipher caesar encrypt 5 file.txt file.enc

Notes:

  • The shift can be any non-negative integer (negative values are not allowed)
  • The effective shift is calculated modulo 26[a-zA-Z]
  • For very large files, performance depends on CPU and SSD
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return caesarRunE(ciphers.Encrypt, params, args)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return caesarPreRunE(cmd, params, args)
		},
	}
	params.addFlags(encryptCmd)

	return encryptCmd
}

func newCaesarDecryptCommand() *cobra.Command {
	params := &CaesarParams{}

	decryptCmd := &cobra.Command{
		Use:   "decrypt <key> <message | input> [output]",
		Short: "Decrypt a given message/file with a shift key",
		Args:  cobra.RangeArgs(2, 3),
		Long: `This command allows decryption of messages or files
using a specified shift value (key).

Each letter in the input is shifted backward in the alphabet
by the specified number. The alphabet wraps around after Z.
Non-alphabetic characters remain unchanged.

A shift of 0 results in no transformation.

Examples:

  Decrypt text:
    1. cipher caesar decrypt 3 "DwwdfnDwGdzq"

  Decrypt a file:
    1. cipher caesar decrypt 5 file.enc file.txt

Notes:

  • The shift can be any non-negative integer (negative values are not allowed)
  • The effective shift is calculated modulo 26[a-zA-Z]
  • For very large files, performance depends on CPU and SSD
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return caesarRunE(ciphers.Decrypt, params, args)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return caesarPreRunE(cmd, params, args)
		},
	}
	params.addFlags(decryptCmd)

	return decryptCmd
}

func newCaesarBruteforceCommand() *cobra.Command {
	params := &CaesarParams{}

	bruteforceCmd := &cobra.Command{
		Use:   "bruteforce <message | input> [output]",
		Short: "Bruteforce a given message/file with all possible shift keys",
		Args:  cobra.RangeArgs(1, 2),
		Long: `This command attempts to decrypt a message or file
by trying all possible shift keys.

Instead of requiring a specific key, the bruteforce mode
iterates through every possible shift (from 1 up to
25) and outputs each resulting candidate.

Each letter in the input is shifted backward in the alphabet
according to the current tested key. The alphabet wraps around after Z.
Non-alphabetic characters remain unchanged.

This is useful when the original shift key is unknown.

Examples:

  Bruteforce text:
    1. cipher caesar bruteforce "DwwdfnDwGdzq"

  Bruteforce a file:
    1. cipher caesar bruteforce file.enc output.txt

Notes:

  • All possible shift values are tested automatically
  • The effective shift is calculated modulo 26[a-zA-Z]
  • For very large files, performance depends on CPU and SSD
  • Output may contain many candidate plaintexts
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return caesarBruteforceRunE(params, args)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return caesarBruteforcePreRunE(cmd, params, args)
		},
	}
	params.addFlags(bruteforceCmd)

	return bruteforceCmd
}

func newCaesarAnalyzeCommand() *cobra.Command {
	analyzeCmd := &cobra.Command{
		Use:   "analyze <message | input>",
		Short: "Analyze a given message/file for a possible shift key",
		Args:  cobra.ExactArgs(1),
		Long: `This command attempts to automatically determine the most
probable shift key of a Caesar-encrypted message or file
using frequency analysis.

Instead of printing all possible shifts, the analyze mode
decrypts the input with every possible key (from 0 to 25)
and scores each result based on how closely it matches
typical English letter frequency.

The scoring method uses statistical comparison (chi-squared)
between the decrypted text and known English letter distributions.
The most likely plaintext appears first in the output.

Non-alphabetic characters remain unchanged during analysis.

This mode is useful when the shift key is unknown and you
want the tool to automatically rank the most probable results.

Examples:

  Analyze text:
    1. cipher caesar analyze "DwwdfnDwGdzq"

  Analyze a file:
    1. cipher caesar analyze file.enc

Notes:

  • All 26 shift values are tested automatically
  • Results are sorted by statistical likelihood
  • Lower score = more probable plaintext
  • Works best with sufficiently large input (recommended ≥ 100 characters)
  • Only alphabetic characters are used for frequency scoring
`,
		RunE: func(cmd *cobra.Command, args []string) error {
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
				fmt.Println(results[i])
			}

			return nil
		},
	}

	return analyzeCmd
}

func caesarPreRunE(command *cobra.Command, params *CaesarParams, args []string) error {
	key, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	} else if key < 0 {
		return fmt.Errorf("key can not be negative: %d", key)
	}
	params.key = key

	sourceMode, err := modeFromArgs(len(args[1:]))
	if err != nil {
		return err
	}
	params.mode = sourceMode

	switch params.mode {
	case ModeMessage:
		return params.parseModeMessageArgs(command)
	case ModeFiles:
		return params.parseModeFilesArgs()
	default:
		return fmt.Errorf("invalid working mode")
	}
}

func caesarRunE(mode ciphers.CipherMode, params *CaesarParams, args []string) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("caesar %s", mode))()
	}

	switch params.mode {
	case ModeMessage:
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

		fmt.Println(string(buffer))

	case ModeFiles:
		inFilePath := args[1]
		outFilePath := args[2]

		blockSizeBytes := params.blockSize * 1024

		caesarCipher, caesarErr := ciphers.NewCaesarCipher(params.key)
		if caesarErr != nil {
			return caesarErr
		}

		engine := engine.NewBlockEngine(blockSizeBytes, params.numCPU)
		return engine.ProcessFile(caesarCipher, mode, inFilePath, outFilePath)
	}

	return nil
}

func caesarBruteforceRunE(params *CaesarParams, args []string) error {
	if isVerbose {
		defer benchmark.MeasurePerformance("caesar bruteforce")()
	}

	switch params.mode {
	case ModeMessage:
		message := args[0]

		buffer := []byte(message)
		dst := bytes.Clone(buffer)

		for i := range 26 {
			caesarCipher, caesarErr := ciphers.NewCaesarCipher(i)
			if caesarErr != nil {
				return caesarErr
			}

			err := caesarCipher.DecryptBlock(dst, buffer)
			if err != nil {
				return err
			}

			fmt.Printf("[%d]: %s\n", i, string(dst))
		}

	case ModeFiles:
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

func caesarBruteforcePreRunE(command *cobra.Command, params *CaesarParams, args []string) error {
	sourceMode, err := modeFromArgs(len(args))
	if err != nil {
		return err
	}
	params.mode = sourceMode

	switch params.mode {
	case ModeMessage:
		return params.parseModeMessageArgs(command)
	case ModeFiles:
		return params.parseModeFilesArgs()
	default:
		return fmt.Errorf("invalid working mode")
	}
}
