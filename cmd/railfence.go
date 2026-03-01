package cmd

import (
	"fmt"
	"strconv"

	"github.com/ItakawaM/go-cryptotool/benchmark"
	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/engine"
	"github.com/spf13/cobra"
)

type RailFenceParams struct {
	key      int
	isVisual bool
	BlockCipherParams
}

func NewRailFenceCommand() *cobra.Command {
	railfenceCmd := &cobra.Command{
		Use:   "railfence",
		Short: "Encrypt or decrypt data using the Rail Fence cipher",
		Long: `The Rail Fence cipher is a classical transposition cipher that writes
plaintext in a zigzag pattern across multiple rails and then reads
it row by row to produce the ciphertext.

This command allows encryption and decryption of messages or files
using a specified number of rails (key).
`,
	}
	railfenceCmd.AddCommand(newRailFenceEncryptCommand(), newRailFenceDecryptCommand())

	return railfenceCmd
}

func newRailFenceEncryptCommand() *cobra.Command {
	params := &RailFenceParams{}

	encryptCmd := &cobra.Command{
		Use:   "encrypt <key> <message | input> [output]",
		Short: "Encrypt a given message/file with a key",
		Args:  cobra.RangeArgs(2, 3),
		Long: `This command allows encryption of messages or files
using a specified number of rails (key).

A key of 1 results in no transformation.

Examples:

  Encrypt text:
    1. cipher railfence encrypt 3 "Canabis"
  
  Encrypt a file:
    1. cipher railfence encrypt 5 file.txt file.enc

Notes:

  • The key must be >= 1
  • Larger keys increase computation time
  • For very large files, performance depends on system memory
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return railfenceRunE(ciphers.Encrypt, params, args)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 3 && params.isVisual {
				return fmt.Errorf("--print can only be used with message encryption")
			}

			return railfencePreRunE(cmd, params, args)
		},
	}
	params.addFlags(encryptCmd)
	encryptCmd.Flags().BoolVarP(&params.isVisual, "print", "p", false, "Print zigzag visualization (text mode only)")

	return encryptCmd
}

func newRailFenceDecryptCommand() *cobra.Command {
	params := &RailFenceParams{}

	decryptCmd := &cobra.Command{
		Use:   "decrypt <key> <message | input> [output]",
		Short: "Decrypt a given message/file with a key",
		Long: `This command allows decryption of messages or files
using a specified number of rails (key).

Examples:

  Decrypt text:
    1. cipher railfence decrypt 3 "nsaaiCb"
  
  Decrypt a file:
    1. cipher railfence decrypt 5 file.enc file.txt

Notes:

  • The key must be >= 1
  • Larger keys increase computation time
  • For very large files, performance depends on system memory
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return railfenceRunE(ciphers.Decrypt, params, args)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return railfencePreRunE(cmd, params, args)
		},
	}
	params.addFlags(decryptCmd)

	return decryptCmd
}

func railfencePreRunE(command *cobra.Command, params *RailFenceParams, args []string) error {
	key, err := strconv.Atoi(args[0])
	if err != nil || key < 1 {
		return fmt.Errorf("key must be >= 1")
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

// Logic
func railfenceRunE(mode ciphers.CipherMode, params *RailFenceParams, args []string) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("railfence %s", mode))()
	}

	switch params.mode {
	case ModeMessage:
		message := args[1]

		railFenceCipher, railFenceErr := ciphers.NewRailFenceCipher(params.key, len(message))
		if railFenceErr != nil {
			return railFenceErr
		}

		if params.isVisual {
			railFenceCipher.Visualize(message)
		}

		src := []byte(message)
		dst := make([]byte, len(src))

		var err error
		switch mode {
		case ciphers.Encrypt:
			err = railFenceCipher.EncryptBlock(dst, src)
		case ciphers.Decrypt:
			err = railFenceCipher.DecryptBlock(dst, src)
		}
		if err != nil {
			return err
		}

		fmt.Println(string(dst))
		return nil

	case ModeFiles:
		inFilePath := args[1]
		outFilePath := args[2]

		blockSizeBytes := params.blockSize * 1024

		railFenceCipher, err := ciphers.NewRailFenceCipher(params.key, blockSizeBytes)
		if err != nil {
			return err
		}

		engine := engine.NewBlockEngine(mode, blockSizeBytes, params.numCPU)
		return engine.ProcessFile(railFenceCipher, inFilePath, outFilePath)

	default:
		return fmt.Errorf("invalid working mode")
	}
}
