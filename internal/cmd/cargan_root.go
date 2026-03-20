package cmd

import (
	"runtime"

	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/spf13/cobra"
)

func NewCardanCommand() *cobra.Command {
	cardanCmd := &cobra.Command{
		Use:   "cardan",
		Short: "Encrypt or decrypt data using the Cardan grille cipher",
		Long: `The Cardan grille is a classical steganographic cipher that uses
a stencil (grille) with holes cut into it. The grille is placed
over a grid, and the plaintext is written through the holes.

After writing the letters, the grille is rotated (usually by
90 degrees) several times, filling the exposed positions each
time until the grid is complete. The final filled grid becomes
the ciphertext.

To decrypt the message, the same grille and rotation order
must be used to reveal the hidden plaintext.

This command allows encryption and decryption of messages or
files using a specified grille pattern and grid size.
`,
	}
	cardanCmd.AddCommand(
		newCardanEncryptCommand(),
		newCardanDecryptCommand(),
		newCardanGenerateKeyCommand(),
	)

	return cardanCmd
}

func newCardanEncryptCommand() *cobra.Command {
	params := &cardanParams{}

	encryptCmd := &cobra.Command{
		Use:   "encrypt [key] <message | input> [output]",
		Short: "Encrypt a message or file using a Cardan grille cipher",
		Args:  cobra.RangeArgs(1, 3),
		Long: `Encrypt messages or files using the Cardan grille cipher.

The Cardan cipher uses a square grille (key) containing holes that
reveal positions in a message grid. Plaintext is written through these
holes, and the grille is rotated (typically four times at 90°) so that
each rotation exposes different cells. Once the grid is filled, the
ciphertext is produced by reading the grid sequentially.

If no key is provided for text encryption, a browser interface will
open to allow interactive grille selection. For file encryption,
a key must be supplied as a JSON file (see the key generation command).

Examples:

  Encrypt text (interactive key selection):
    1. go-cryptotool cardan encrypt "HELLO WORLD"

  Encrypt text with a key:
    1. go-cryptotool cardan encrypt key.json "HELLO WORLD"

  Encrypt a file:
    1. go-cryptotool cardan encrypt key.json file.txt file.enc

Notes:

  • The key defines the grille size and hole positions
  • A valid grille must cover every grid cell exactly once across all rotations
  • Messages shorter than the grid may be padded automatically
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cardanRunE(cmd, args, params, ciphers.Encrypt)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return cardanPreRunE(cmd, args, params)
		},
	}
	// cant use params.addFlags, because of block
	encryptCmd.Flags().IntVarP(&params.numCPU, "threads", "t", runtime.NumCPU()/2, "Amount of threads to be used")

	return encryptCmd
}

func newCardanDecryptCommand() *cobra.Command {
	params := &cardanParams{}

	decryptCmd := &cobra.Command{
		Use:   "decrypt <key> <message | input> [output]",
		Short: "Decrypt a message or file using a Cardan grille cipher",
		Args:  cobra.RangeArgs(2, 3),
		Long: `Decrypt messages or files that were encrypted using the Cardan grille cipher.

The Cardan cipher uses a square grille (key) containing holes that
reveal positions in a message grid. During decryption, the ciphertext
is written into the grid and the grille is applied in the same rotation
sequence (typically four 90° rotations). Characters revealed through
the grille holes are read in order to reconstruct the original plaintext.

A key must be provided for decryption and should match the one used
during encryption. Keys are supplied as JSON files (see the key
generation command).

Examples:

  Decrypt text:
    1. go-cryptotool cardan decrypt key.json "ENCRYPTEDTEXT"

  Decrypt a file:
    1. go-cryptotool cardan decrypt key.json file.enc file.txt

Notes:

  • The key must match the grille used for encryption
  • The grille defines the grid size and hole positions
  • Incorrect keys will produce invalid plaintext
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cardanRunE(cmd, args, params, ciphers.Decrypt)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return cardanPreRunE(cmd, args, params)
		},
	}
	// cant use params.addFlags, because of block
	decryptCmd.Flags().IntVarP(&params.numCPU, "threads", "t", runtime.NumCPU()/2, "Amount of threads to be used")

	return decryptCmd
}

func newCardanGenerateKeyCommand() *cobra.Command {
	params := &cardanParams{}

	generateCmd := &cobra.Command{
		Use:   "generate-key <size> <output>",
		Short: "Generate a valid Cardan grille key",
		Args:  cobra.ExactArgs(2),
		Long: `Generate a valid Cardan grille key for use with the Cardan cipher.

The Cardan cipher requires a square grille containing holes that reveal
positions in a message grid. During encryption and decryption, the grille
is rotated (typically four times at 90°), and each rotation must expose
different cells of the grid.

This command generates a grille where the hole positions are arranged so
that every cell of the grid is covered exactly once across all rotations.
The generated key is saved as a JSON file and can later used with the
encrypt and decrypt commands.

Examples:

  Generate a key for a 4x4 grid:
    1. go-cryptotool cardan generate-key 4 key4.json

  Generate a key for a 5x5 grid:
    1. go-cryptotool cardan generate-key 5 key5.json

Notes:

  • The size defines the dimensions of the grille (size x size)
  • The generated grille guarantees non-overlapping rotations
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cardanGenerateKeyRunE(cmd, args, params)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return cardanGenerateKeyPreRunE(args, params)
		},
	}

	return generateCmd
}
