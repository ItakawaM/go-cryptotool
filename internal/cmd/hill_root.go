package cmd

import (
	"github.com/ItakawaM/arcipher/ciphers"
	"github.com/spf13/cobra"
)

func NewHillCommand() *cobra.Command {
	hillCmd := &cobra.Command{
		Use:   "hill",
		Short: "Encrypt or decrypt data using the Hill cipher",
		Long: `The Hill cipher is a classical polygraphic substitution cipher
that uses linear algebra to transform blocks of text into ciphertext.

It operates on fixed-size vectors of characters, which are multiplied
by an invertible key matrix under modular arithmetic (modulo 26).
Each block of plaintext is treated as a vector and transformed into a
ciphertext vector using the key.

Only ASCII characters a-zA-Z are processed by the cipher.
All other characters are left unchanged. 

If the input length is not a multiple of the key size, 
the remaining characters that cannot form a complete vector may be left unencrypted.
`,
	}
	hillCmd.AddCommand(
		newHillGenerateKeyCommand(),
		newHillEncryptCommand(),
		newHillDecryptCommand(),
	)

	return hillCmd
}

func newHillEncryptCommand() *cobra.Command {
	params := &hillParams{}

	encryptCmd := &cobra.Command{
		Use:   "encrypt <key> <message | input> [output]",
		Short: "Encrypt a message or file using the Hill cipher",
		Args:  cobra.RangeArgs(2, 3),
		Long: `Encrypt messages or files using the Hill cipher.

A key must be provided for encryption and should be an invertible NxN
matrix under modular arithmetic (mod 26). Keys are supplied
as JSON files (see the key generation command).

The Hill cipher operates on fixed-size blocks of text, transforming
each block using matrix multiplication.

Examples:

  Encrypt text with key:
    arcipher hill encrypt ./key.json "HELLOWORLD"

  Encrypt a file with key and 4 threads:
    arcipher hill encrypt key.json ./example/input ./example/input.enc --threads 4 -v

Notes:

  • The key matrix must be invertible modulo 26
  • Only ASCII characters a-zA-Z are encrypted
  • All non-alphabetic characters are left unchanged
  • Remaining characters that do not fill a complete vector of N may be left unencrypted
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return hillRunE(cmd, args, params, ciphers.Encrypt)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return hillPreRunE(cmd, args, params)
		},
	}
	params.addFlags(encryptCmd)

	return encryptCmd
}

func newHillDecryptCommand() *cobra.Command {
	params := &hillParams{}

	decryptCmd := &cobra.Command{
		Use:   "decrypt <key> <message | input> [output]",
		Short: "Decrypt a message or file using the Hill cipher",
		Args:  cobra.RangeArgs(2, 3),
		Long: `Decrypt messages or files that were encrypted using the Hill cipher.

A key must be provided for decryption and should match the one used
during encryption. Keys are supplied as JSON files (see the key
generation command).

During decryption, the modular inverse of the NxN key
matrix is used to recover the original plaintext.

Examples:

  Decrypt text with key:
    arcipher hill decrypt ./key.json "ZICVTWQNGRZGVTWAVZHCQYGLMGJ"

  Decrypt a file with key and 4 threads:
    arcipher hill decrypt key.json ./example/input.enc ./example/output --threads 4 -v

Notes:

  • The key matrix must be invertible modulo 26
  • Only ASCII characters a-zA-Z are encrypted
  • All non-alphabetic characters are left unchanged
  • Remaining characters that do not fill a complete vector of N may be left unencrypted
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return hillRunE(cmd, args, params, ciphers.Decrypt)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return hillPreRunE(cmd, args, params)
		},
	}
	params.addFlags(decryptCmd)

	return decryptCmd
}

func newHillGenerateKeyCommand() *cobra.Command {
	params := &hillParams{}

	generateCmd := &cobra.Command{
		Use:   "generate-key <size> <output>",
		Short: "Generate a valid Hill cipher key",
		Args:  cobra.ExactArgs(2),
		Long: `Generate a valid Hill cipher key matrix for use with the Hill cipher.

This command generates an invertible matrix under modular arithmetic,
which is required for both encryption and decryption in the Hill cipher.
The matrix is constructed so that its determinant is coprime with the
alphabet size (26), ensuring that a modular inverse exists.

The generated key is saved as a JSON file and can later be used with the
encrypt and decrypt commands.

Must be > 1.

Examples:

  Generate a 3x3 Hill cipher key:
    arcipher hill generate-key 3 key.json

  Generate a 25x25 Hill cipher template-key (all zeroes):
    arcipher hill generate-key 25 key.json --template

Notes:

  • The size defines the dimensions of the key matrix (size x size)
  • The key is generated such that gcd(det(matrix), 26) = 1
  • Only invertible matrices modulo 26 are valid for the Hill cipher
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return hillGenerateKeyRunE(cmd, args, params)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return hillGenerateKeyPreRunE(args, params)
		},
	}
	generateCmd.Flags().BoolVarP(&params.isTemplate, "template", "t", false, "Generate a zero matrix key")

	return generateCmd
}
