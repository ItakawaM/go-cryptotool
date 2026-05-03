package cmd

import (
	"github.com/ItakawaM/arcipher/ciphers"
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

  Encrypt text with key 15:
    arcipher caesar encrypt 15 "helloworld"

  Encrypt a file with key 5 using 2 threads and blocks of 256KB:
    arcipher caesar encrypt 5 ./example/SunPoem ./example/SunPoem.enc --block 256 --threads 2

Notes:

  • The shift can be any integer 
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

  Decrypt text with key 15:
    arcipher caesar decrypt 15 "wtaadldgas"

  Decrypt a file with key 5 using 2 threads and blocks of 256KB:
    arcipher caesar decrypt 5 ./example/SunPoem.enc ./example/SunPoem --block 256 --threads 2

Notes:

  • The shift can be any integer
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
    arcipher caesar bruteforce "wtaadldgas"

  Bruteforce a file using 6 threads and blocks of 2048KB:
    arcipher caesar bruteforce ./example/SunPoem ./example/SunPoem_Directory -t 6 -b 2048

Notes:

  • All possible shift values are tested automatically
  • The effective shift is calculated modulo 26[a-zA-Z]
  • Output may contain many candidate plaintexts
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return caesarBruteforceRunE(args, params)
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
    arcipher caesar analyze "wtaadldgas"

  Analyze a file:
    arcipher caesar analyze ./example/SunPoem

Notes:

  • All 26 shift values are tested automatically
  • Results are sorted by statistical likelihood
  • Lower score = more probable plaintext
  • Works best with sufficiently large input (recommended ≥ 100 characters)
  • Only alphabetic characters are used for frequency scoring
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return caesarAnalyzeRunE(args)
		},
	}

	return analyzeCmd
}
