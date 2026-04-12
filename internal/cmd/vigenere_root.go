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
		newVigenereBruteforceAttack(),
		newVigenereAnalyzeCommand(),
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
	encryptCmd.Flags().BoolVarP(&factory.autokey, "autokey", "a", false, "Enable autokey variant")

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
	decryptCmd.Flags().BoolVarP(&factory.autokey, "autokey", "a", false, "Enable autokey variant")

	return decryptCmd
}

func newVigenereBruteforceAttack() *cobra.Command {
	params := &vigenereBruteforceParams{}
	var autokey bool

	bruteforceCmd := &cobra.Command{
		Use:   "bruteforce <wordlist> <message | input> [output]",
		Short: "Attempt to decrypt a message/file using a dictionary of possible Vigenère keys",
		Args:  cobra.RangeArgs(2, 3),
		Long: `This command attempts to decrypt a message or file
encrypted with the Vigenère cipher by trying keys from a provided wordlist.

Each word in the wordlist is used as a candidate key to decrypt the input.
Non-alphabetic characters remain unchanged.

Examples:

  Bruteforce text using a wordlist:
    1. go-cryptotool vigenere bruteforce wordlist.txt "LxfopvEfRnhr"

  Bruteforce a file:
    1. go-cryptotool vigenere bruteforce wordlist.txt file.enc output_directory

Notes:

  • Each word in the wordlist is treated as a potential key
  • Non-alphabetic keys are skipped
  • Decryption is performed using each candidate key
  • Output may contain many candidate plaintexts
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return vigenereBruteforceRunE(args, params, autokey)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return vigenereBruteforcePreRunE(cmd, args, params)
		},
	}
	params.addFlags(bruteforceCmd)
	bruteforceCmd.Flags().BoolVarP(&autokey, "autokey", "a", false, "Enable autokey variant")

	return bruteforceCmd
}

func newVigenereAnalyzeCommand() *cobra.Command {
	analyzeCmd := &cobra.Command{
		Use:   "analyze <message | input>",
		Short: "Attempt to recover the Vigenère key using Kasiski examination and frequency analysis",
		Args:  cobra.ExactArgs(1),
		Long: `This command analyzes a message or file encrypted with the Vigenère cipher
to estimate the most likely key.

It first applies the Kasiski examination to determine probable key lengths by
detecting repeated substrings and analyzing the distances between them.
Then, for each candidate key length, it performs frequency analysis on
each segment of the ciphertext to recover the most likely key.

Examples:

  Analyze ciphertext from input text:
    1. go-cryptotool vigenere analyze "SOMETEXTHERE"

  Analyze a file:
    1. go-cryptotool vigenere analyze file.enc

Notes:

  • Repeated substrings are used to estimate key length candidates
  • Frequency analysis is applied to recover the key from each candidate length
  • Output may include multiple possible keys
  • Non-alphabetic characters are ignored during analysis
  • Works best on longer ciphertexts with typical language distribution
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return vigenereAnalyzeRunE(args)
		},
	}

	return analyzeCmd
}
