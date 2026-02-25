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

type caesarParams struct {
	key byte
	blockCipherParams
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
	caesarCmd.AddCommand(newCaesarEncryptCommand(), newCaesarDecryptCommand())

	return caesarCmd
}

func newCaesarEncryptCommand() *cobra.Command {
	params := &caesarParams{}

	encryptCmd := &cobra.Command{
		Use:   "encrypt <key> <message | input> [output]",
		Short: "Encrypt a given message/file with a shift key",
		Args:  cobra.RangeArgs(2, 3),
		Long: `This command allows encryption of messages or files
using a specified shift value (key).

Each letter in the input is shifted forward in the alphabet
by the specified number. The alphabet wraps around after Z.
Non-alphabetic and non-numeric characters remain unchanged.

A shift of 0 results in no transformation.

Examples:

  Encrypt text:
    1. cipher caesar encrypt 3 "AttackAtDawn"

  Encrypt a file:
    1. cipher caesar encrypt 5 file.txt file.enc

Notes:

  • The shift can be any non-negative integer (negative values are not allowed)
  • The effective shift is calculated modulo len(language)
  • For very large files, performance depends on CPU
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return caesarRunE(ciphers.Encrypt, params, args)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return caesarPreRunE(cmd, params, args)
		},
	}

	addFlags(encryptCmd, &params.blockCipherParams)

	return encryptCmd
}

func newCaesarDecryptCommand() *cobra.Command {
	params := &caesarParams{}

	decryptCmd := &cobra.Command{
		Use:   "decrypt <key> <message | input> [output]",
		Short: "Decrypt a given message/file with a shift key",
		Args:  cobra.RangeArgs(2, 3),
		Long: `This command allows decryption of messages or files
using a specified shift value (key).

Each letter in the input is shifted backward in the alphabet
by the specified number. The alphabet wraps around before
the first character of the selected language set.
Non-alphabetic and non-numeric characters remain unchanged.

A shift of 0 results in no transformation.

Examples:

  Decrypt text:
    1. cipher caesar decrypt 3 "DwwdfnDwGdzq"

  Decrypt a file:
    1. cipher caesar decrypt 5 file.enc file.txt

Notes:

  • The shift can be any non-negative integer (negative values are not allowed)
  • The effective shift is calculated modulo len(language)
  • For very large files, performance depends on CPU
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return caesarRunE(ciphers.Decrypt, params, args)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return caesarPreRunE(cmd, params, args)
		},
	}

	addFlags(decryptCmd, &params.blockCipherParams)

	return decryptCmd
}

func caesarPreRunE(command *cobra.Command, params *caesarParams, args []string) error {
	key, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	if key < 0 {
		return fmt.Errorf("key can not be negative: %d", key)
	}

	params.key = byte(key % 26) // TODO: CHANGE HARDCODED VALUE

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

func caesarRunE(mode ciphers.Mode, params *caesarParams, args []string) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("caesar %s", mode))()
	}

	if len(args) == 2 {
		message := args[1]

		caesarCipher := ciphers.NewCaesarCipher(params.key, len(message), 1)

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
	} else {
		inFilePath := args[1]
		outFilePath := args[2]

		blockSizeBytes := params.blockSize * 1024

		caesarCipher := ciphers.NewCaesarCipher(params.key, blockSizeBytes, params.numCPU)

		err := engine.ProcessFile(caesarCipher, mode, inFilePath, outFilePath)
		if err != nil {
			return err
		}
	}

	return nil
}
