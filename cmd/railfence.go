package cmd

import (
	"fmt"
	"slices"

	"github.com/ItakawaM/go-cryptotool/benchmark"
	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/engine"
	"github.com/spf13/cobra"
)

// Flags
var (
	message        string
	inputFilePath  string
	outputFilePath string
	key            int
	blockSize      int
	allowedBlock   = []int{16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}
)

func addFlags(command *cobra.Command, mode string) {
	command.Flags().StringVarP(&message, "message", "m", "", fmt.Sprintf("Message to %s", mode))
	command.Flags().StringVarP(&inputFilePath, "input", "i", "", fmt.Sprintf("Path to file to %s", mode))
	command.Flags().StringVarP(&outputFilePath, "output", "o", "", "Path to output file")
	command.Flags().IntVarP(&key, "key", "k", 1, "Cipher algorithm key")
	command.Flags().IntVarP(&blockSize, "block", "b", 64, "Block size (KB): 16 32 64 128 256 512 1024 2048 4096 8192 16384")

	command.MarkFlagRequired("key")
	command.MarkFlagsRequiredTogether("input", "output")
	command.MarkFlagsMutuallyExclusive("message", "input")
	command.MarkFlagsMutuallyExclusive("message", "block")
}

func railfencePreRunE() error {
	if key < 1 {
		return fmt.Errorf("provided --key must be >=1")
	}

	if !slices.Contains(allowedBlock, blockSize) {
		return fmt.Errorf("Provided block size[%d] is not viable!", blockSize)
	}
	blockSize *= 1024 // Convert to KB

	return nil
}

// Logic
func railfenceRunE(mode ciphers.Mode) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("railfence %s", ciphers.Mode.ToString(mode)))()
	}

	railFenceCipher := ciphers.NewRailFenceCipher(key)
	if message != "" {
		bytes := []byte(message)
		buffer := make([]byte, len(bytes))

		var err error
		switch mode {
		case ciphers.Encrypt:
			err = railFenceCipher.EncryptBlock(bytes, buffer)
		case ciphers.Decrypt:
			err = railFenceCipher.DecryptBlock(bytes, buffer)
		}
		if err != nil {
			return err
		}

		fmt.Println(string(bytes))
	} else {
		err := engine.ProcessFile(mode, inputFilePath, outputFilePath, railFenceCipher, int64(blockSize))
		if err != nil {
			return err
		}
	}

	return nil
}

// railfenceCmd represents the railfence command.
var railfenceCmd = &cobra.Command{
	Use:   "railfence",
	Short: "Encrypt or decrypt data using the Rail Fence cipher",
	Long: `The Rail Fence cipher is a classical transposition cipher that writes
plaintext in a zigzag pattern across multiple rails and then reads
it row by row to produce the ciphertext.

This command allows encryption and decryption of messages or files
using a specified number of rails (key).
`,
}

// encryptCmd represents the encrypt command.
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a given message with a key",
	Long: `This command allows encryption of messages or files
using a specified number of rails (key).

A key of 1 results in no transformation.

Examples:

  Encrypt text:
    1. cipher railfence encrypt --key 3 --message "Canabis"
  
  Encrypt a file:
    1. cipher railfence encrypt --key 5 --input file.txt --output file.enc

Notes:

  • The key must be >= 1
  • Larger keys increase computation time
  • For very large files, performance depends on system memory
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return railfenceRunE(ciphers.Encrypt)
	},
}

// decryptCmd represents the decrypt command.
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a given message with a key",
	Long: `This command allows decryption of messages or files
using a specified number of rails (key).

Examples:

  Decrypt text:
    1. cipher railfence decrypt --key 3 --message "nsaaiCb"
  
  Decrypt a file:
    1. cipher railfence decrypt --key 5 --input file.enc --output file.txt

Notes:

  • The key must be >= 1
  • Larger keys increase computation time
  • For very large files, performance depends on system memory
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return railfenceRunE(ciphers.Decrypt)
	},
}

func init() {
	rootCmd.AddCommand(railfenceCmd)
	railfenceCmd.AddCommand(encryptCmd)
	railfenceCmd.AddCommand(decryptCmd)

	railfenceCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return railfencePreRunE()
	}

	addFlags(encryptCmd, "encrypt")
	addFlags(decryptCmd, "decrypt")

}
