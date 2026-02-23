package cmd

import (
	"fmt"
	"runtime"
	"slices"
	"strconv"

	"github.com/ItakawaM/go-cryptotool/benchmark"
	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/engine"
	"github.com/spf13/cobra"
)

type railFenceParams struct {
	key      int
	isVisual bool
	blockCipherParams
}

var allowedBlockSizes = []int{
	16, 32, 64, 128, 256, 512,
	1024, 2048, 4096, 8192, 16384,
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
	params := &railFenceParams{}

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

	addFlags(encryptCmd, &params.blockCipherParams)
	encryptCmd.Flags().BoolVarP(&params.isVisual, "print", "p", false, "Print zigzag visualization (text mode only)")

	return encryptCmd
}

func newRailFenceDecryptCommand() *cobra.Command {
	params := &railFenceParams{}

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

	addFlags(decryptCmd, &params.blockCipherParams)

	return decryptCmd
}

func railfencePreRunE(command *cobra.Command, params *railFenceParams, args []string) error {
	key, err := strconv.Atoi(args[0])
	if err != nil || key < 1 {
		return fmt.Errorf("key must be >= 1")
	}
	params.key = key

	if len(args) == 2 {
		if command.Flags().Changed("block") {
			return fmt.Errorf("--block can only be used when processing files")
		}

		if command.Flags().Changed("threads") {
			return fmt.Errorf("--threads can only be used when processing files")
		}

		return nil
	}

	if !slices.Contains(allowedBlockSizes, params.blockSize) {
		return fmt.Errorf("invalid block size: %d", params.blockSize)
	}

	if params.numCPU <= 0 {
		return fmt.Errorf("invalid thread count: %d", params.numCPU)
	} else if params.numCPU > runtime.NumCPU() {
		params.numCPU = runtime.NumCPU()
	}

	return nil
}

// Logic
func railfenceRunE(mode ciphers.Mode, params *railFenceParams, args []string) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("railfence %s", mode))()
	}

	if len(args) == 2 {
		message := args[1]

		railFenceCipher := ciphers.NewRailFenceCipher(params.key, len(message), 1)
		railFenceCipher.BuildPermutationTable()

		src := []byte(message)
		dst := make([]byte, len(src))

		if params.isVisual {
			railFenceCipher.Visualize(message)
		}

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
	} else {
		inFilePath := args[1]
		outFilePath := args[2]

		blockSizeBytes := params.blockSize * 1024

		railFenceCipher := ciphers.NewRailFenceCipher(params.key, blockSizeBytes, params.numCPU)
		railFenceCipher.BuildPermutationTable()

		err := engine.ProcessFile(railFenceCipher, mode, inFilePath, outFilePath)
		if err != nil {
			return err
		}
	}

	return nil
}
