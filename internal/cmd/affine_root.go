package cmd

import (
	"github.com/ItakawaM/arcipher/ciphers"
	"github.com/spf13/cobra"
)

func NewAffineCommand() *cobra.Command {
	affineCmd := &cobra.Command{
		Use:   "affine",
		Short: "Encrypt or decrypt data using the Affine cipher",
		Long: `The Affine cipher is a classical polygraphic substitution cipher.

It operates on fixed-size blocks of ASCII a-zA-Z characters. Each block
is treated as a vector and transformed using the affine map:

    ciphertext = (M * plaintext + b) mod 26

Where M is an invertible NxN matrix key and b is an N-dimensional vector key.
Non-alphabetic characters are passed through unchanged. 

If the input containsa number of alphabetic characters that is not a multiple of N, the trailing
remainder is left unencrypted.
`,
	}
	affineCmd.AddCommand(
		newAffineGenerateKeyCommand(),
		newAffineEncryptCommand(),
		newAffineDecryptCommand(),
	)

	return affineCmd
}

func newAffineEncryptCommand() *cobra.Command {
	params := &affineParams{}

	encryptCmd := &cobra.Command{
		Use:   "encrypt <key> <message | input> [output]",
		Short: "Encrypt a message or file using the Affine cipher",
		Args:  cobra.RangeArgs(2, 3),
		Long: `Encrypt messages or files using the Affine cipher.

A key must be provided as a JSON file (see: arcipher affine generate-key).
The key consists of an invertible NxN matrix and an N-dimensional vector,
both operating under modulo 26 arithmetic.

Examples:

  Encrypt text with key:
    arcipher affine encrypt ./key.json "HELLOWORLD"

  Encrypt a file with key and 4 threads:
    arcipher affine encrypt key.json ./example/input ./example/input.enc --threads 4 -v

Notes:

  • The key matrix must be invertible modulo 26
  • Only ASCII a-zA-Z characters are encrypted; all others pass through unchanged
  • Alphabetic characters that do not fill a complete block of N are left unencrypted
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return affineRunE(cmd, args, params, ciphers.Encrypt)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return affinePreRunE(cmd, args, params)
		},
	}
	params.addFlags(encryptCmd)

	return encryptCmd
}

func newAffineDecryptCommand() *cobra.Command {
	params := &affineParams{}

	decryptCmd := &cobra.Command{
		Use:   "decrypt <key> <message | input> [output]",
		Short: "Decrypt a message or file using the Affine cipher",
		Args:  cobra.RangeArgs(2, 3),
		Long: `Decrypt messages or files that were encrypted using the Affine cipher.

A key must be provided as a JSON file (see: arcipher affine generate-key) and must
match the one used during encryption.

Examples:

  Decrypt text with key:
    arcipher affine decrypt ./key.json "ZICVTWQNGRZGVTWAVZHCQYGLMGJ"

  Decrypt a file with key and 4 threads:
    arcipher affine decrypt key.json ./example/input.enc ./example/output --threads 4 -v

Notes:

  • The key matrix must be invertible modulo 26
  • Only ASCII a-zA-Z characters are decrypted; all others pass through unchanged
  • Alphabetic characters that do not fill a complete block of N are left undecrypted
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return affineRunE(cmd, args, params, ciphers.Decrypt)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return affinePreRunE(cmd, args, params)
		},
	}
	params.addFlags(decryptCmd)

	return decryptCmd
}

func newAffineGenerateKeyCommand() *cobra.Command {
	params := &affineParams{}

	generateCmd := &cobra.Command{
		Use:   "generate-key <size> <output>",
		Short: "Generate a valid Affine cipher key",
		Args:  cobra.ExactArgs(2),
		Long: `Generate a random Affine cipher key and save it as a JSON file.

The key consists of a random invertible NxN matrix M and a random N-dimensional
vector b, where N is the given size. Both are valid for use immediately with
the encrypt and decrypt commands.

The size argument must be > 0.

Examples:

  Generate a 3x3 Affine cipher key:
    arcipher affine generate-key 3 key.json

  Generate a 25x25 Affine cipher template key (all zeroes):
    arcipher affine generate-key 25 key.json --template

Notes:

  • M is guaranteed invertible modulo 26: gcd(det(M), 26) = 1
  • b is a randomly generated vector of N values in [0, 25]
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return affineGenerateKeyRunE(cmd, args, params)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return affineGenerateKeyPreRunE(args, params)
		},
	}
	generateCmd.Flags().BoolVarP(&params.isTemplate, "template", "t", false, "Generate a zero matrix key")

	return generateCmd
}
