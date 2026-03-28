package cmd

import (
	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/spf13/cobra"
)

func NewVigenereCommand() *cobra.Command {
	vigenereCmd := &cobra.Command{
		Use:   "vigenere",
		Short: "Encrypt or decrypt data using the Vigenère cipher",
		Long: `The Vigenère cipher is a classical polyalphabetic substitution cipher
that uses a keyword to apply multiple Caesar shifts across the plaintext.

Each letter in the keyword determines the shift for the corresponding
letter in the message. The keyword is repeated as needed to match the
length of the plaintext.
`,
	}
	vigenereCmd.AddCommand(
		newVigenereEncryptCommand(),
		newVigenereDecryptCommand(),
	)

	return vigenereCmd
}

func newVigenereEncryptCommand() *cobra.Command {
	params := &blockCipherParams{}
	factory := &vigenereFactory{}

	encryptCmd := &cobra.Command{
		Use:   "encrypt <keyword> <message | input> [output]",
		Short: "Encrypt a given message/file with a keyword",
		Args:  cobra.RangeArgs(2, 3),
		Long: `This command allows encryption of messages or files
using the Vigenère cipher with a specified keyword.

Non-alphabetic characters remain unchanged and do not
consume characters from the keyword.

Examples:

  Encrypt text:
    1. go-cryptotool vigenere encrypt KEY "AttackAtDawn"

  Encrypt a file:
    1. go-cryptotool vigenere encrypt SECRET file.txt file.enc

Notes:

  • The keyword must consist of alphabetic characters only [a-zA-Z]
  • Letter shifts are derived from keyword characters (A=0, B=1, ..., Z=25)
  • The keyword is case-insensitive (but case can be preserved in output)
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

func newVigenereDecryptCommand() *cobra.Command {
	params := &blockCipherParams{}
	factory := &vigenereFactory{}

	decryptCmd := &cobra.Command{
		Use:   "decrypt <keyword> <message | input> [output]",
		Short: "Decrypt a given message/file with a keyword",
		Args:  cobra.RangeArgs(2, 3),
		Long: `This command allows decryption of messages or files
using the Vigenère cipher with a specified keyword.

Non-alphabetic characters remain unchanged and do not
consume characters from the keyword.

Examples:

  Decrypt text:
    1. go-cryptotool vigenere decrypt KEY "KxrkgiKxBkal"

  Decrypt a file:
    1. go-cryptotool vigenere decrypt SECRET file.enc file.txt

Notes:

  • The keyword must consist of alphabetic characters only [a-zA-Z]
  • Letter shifts are derived from keyword characters (A=0, B=1, ..., Z=25)
  • The keyword is case-insensitive (but case can be preserved in output)
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
