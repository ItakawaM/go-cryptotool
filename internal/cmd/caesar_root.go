package cmd

import (
	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/spf13/cobra"
)

func NewCaesarCommand() *cobra.Command {
	caesarCmd := &cobra.Command{
		Use:   "caesar",
		Short: "Encrypt or decrypt data using the Caesar cipher",
		Long: `The Caesar cipher is a classical substitution cipher that shifts
each letter in the plaintext by a fixed number of positions
down the alphabet.
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
	params := &blockCipherParams{}
	factory := &caesarFactory{}

	encryptCmd := &cobra.Command{
		Use:   "encrypt <key> <message | input> [output]",
		Short: "Encrypt a given message/file with a shift key",
		Args:  cobra.RangeArgs(2, 3),
		Long: `This command allows encryption of messages or files
using a specified shift value (key).

Non-alphabetic characters remain unchanged.
A shift of 0 results in no transformation.

Examples:

  Encrypt text:
    1. go-cryptotool caesar encrypt 3 "AttackAtDawn"

  Encrypt a file:
    1. go-cryptotool caesar encrypt 5 file.txt file.enc

Notes:

  • The shift can be any non-negative integer (negative values are not allowed)
  • The effective shift is calculated modulo 26[a-zA-Z]
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return simpleCipherRunE(cmd, args, factory, params, ciphers.Encrypt)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return simpleCipherPreRunE(cmd, args, factory, params)
		},
	}
	params.addFlags(encryptCmd)

	return encryptCmd
}

func newCaesarDecryptCommand() *cobra.Command {
	params := &blockCipherParams{}
	factory := &caesarFactory{}

	decryptCmd := &cobra.Command{
		Use:   "decrypt <key> <message | input> [output]",
		Short: "Decrypt a given message/file with a shift key",
		Args:  cobra.RangeArgs(2, 3),
		Long: `This command allows decryption of messages or files
using a specified shift value (key).

Non-alphabetic characters remain unchanged.
A shift of 0 results in no transformation.

Examples:

  Decrypt text:
    1. go-cryptotool caesar decrypt 3 "DwwdfnDwGdzq"

  Decrypt a file:
    1. go-cryptotool caesar decrypt 5 file.enc file.txt

Notes:

  • The shift can be any non-negative integer (negative values are not allowed)
  • The effective shift is calculated modulo 26[a-zA-Z]
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return simpleCipherRunE(cmd, args, factory, params, ciphers.Decrypt)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return simpleCipherPreRunE(cmd, args, factory, params)
		},
	}
	params.addFlags(decryptCmd)

	return decryptCmd
}

func newCaesarBruteforceCommand() *cobra.Command {
	params := &blockCipherParams{}

	bruteforceCmd := &cobra.Command{
		Use:   "bruteforce <message | input> [output]",
		Short: "Bruteforce a given message/file with all possible shift keys",
		Args:  cobra.RangeArgs(1, 2),
		Long: `This command attempts to decrypt a message or file
by trying all possible shift keys.

Non-alphabetic characters remain unchanged.
This is useful when the original shift key is unknown.

Examples:

  Bruteforce text:
    1. go-cryptotool caesar bruteforce "DwwdfnDwGdzq"

  Bruteforce a file:
    1. go-cryptotool caesar bruteforce file.enc output_directory

Notes:

  • All possible shift values are tested automatically
  • The effective shift is calculated modulo 26[a-zA-Z]
  • Output may contain many candidate plaintexts
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return caesarBruteforceRunE(cmd, args, params)
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

The scoring method uses statistical comparison (chi-squared)
between the decrypted text and known English letter distributions.
The most likely plaintext appears first in the output.

Non-alphabetic characters remain unchanged during analysis.

Examples:

  Analyze text:
    1. go-cryptotool caesar analyze "DwwdfnDwGdzq"

  Analyze a file:
    1. go-cryptotool caesar analyze file.enc

Notes:

  • All 26 shift values are tested automatically
  • Results are sorted by statistical likelihood
  • Lower score = more probable plaintext
  • Works best with sufficiently large input (recommended ≥ 100 characters)
  • Only alphabetic characters are used for frequency scoring
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return caesarAnalyzeRunE(cmd, args)
		},
	}

	return analyzeCmd
}
