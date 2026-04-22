package cmd

import "github.com/spf13/cobra"

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
	)

	return hillCmd
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
