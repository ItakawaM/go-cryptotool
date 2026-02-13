package cmd

import (
	"fmt"
	"time"

	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/engine"
	"github.com/spf13/cobra"
)

var (
	message        string
	inputFilePath  string
	outputFilePath string
	key            int
	// blocksize int
)

func addFlags(command *cobra.Command, mode string) {
	command.Flags().StringVarP(&message, "message", "m", "", fmt.Sprintf("Message to %s", mode))
	command.Flags().StringVarP(&inputFilePath, "input", "i", "", fmt.Sprintf("Path to file to %s", mode))
	command.Flags().StringVarP(&outputFilePath, "output", "o", "", "Path to output file")
	command.Flags().IntVarP(&key, "key", "k", 0, "Cipher algorithm key")

	command.MarkFlagRequired("key")
}

func validateMessageOrInput() error {
	if message == "" && inputFilePath == "" {
		return fmt.Errorf("must provide --message or --input")
	}

	if message != "" && inputFilePath != "" {
		return fmt.Errorf("cannot use both --message and --input")
	}

	if message != "" && outputFilePath != "" {
		return fmt.Errorf("cannot use both --message and --output")
	}

	if inputFilePath != "" && outputFilePath == "" {
		return fmt.Errorf("--output is required with --input")
	}

	return nil
}

func validateKey() error {
	if key < 1 {
		return fmt.Errorf("provided --key must be >=1")
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

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a given message with a key",
	Long: `This command allows encryption of messages or files
using a specified number of rails (key).

A key of 1 results in no transformation.

Examples:

  Decrypt text:
    1. cipher railfence encrypt --key 3 --message "Canabis"
  
  Decrypt a file:
    1. cipher railfence encrypt --key 5 --input file.txt --output file.enc

Notes:

  • The key must be >= 1
  • Larger keys increase computation time
  • For very large files, performance depends on system memory
`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := validateMessageOrInput(); err != nil {
			return err
		}

		if err := validateKey(); err != nil {
			return err
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		startTime := time.Now()

		railFenceCipher := ciphers.NewRailFenceCipher(key)
		if message != "" {
			bytes := []byte(message)
			if err := railFenceCipher.DecryptBlock(bytes); err != nil {
				return err
			}

			fmt.Println(string(bytes))
		} else {
			err := engine.ProcessFile("encrypt", inputFilePath, outputFilePath, railFenceCipher)
			if err != nil {
				return err
			}
		}

		if Verbose {
			fmt.Printf("Time: %s", time.Since(startTime))
		}

		return nil
	},
}

// decryptCmd represents the encrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a given message with a key",
	// TODO: Change Long Description
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
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := validateMessageOrInput(); err != nil {
			return err
		}

		if err := validateKey(); err != nil {
			return err
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		startTime := time.Now()

		railFenceCipher := ciphers.NewRailFenceCipher(key)
		if message != "" {
			bytes := []byte(message)
			if err := railFenceCipher.EncryptBlock(bytes); err != nil {
				return err
			}

			fmt.Println(string(bytes))
		} else {
			err := engine.ProcessFile("decrypt", inputFilePath, outputFilePath, railFenceCipher)
			if err != nil {
				return err
			}
		}

		if Verbose {
			fmt.Printf("Time: %s", time.Since(startTime))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(railfenceCmd)
	railfenceCmd.AddCommand(encryptCmd)
	railfenceCmd.AddCommand(decryptCmd)

	addFlags(encryptCmd, "encrypt")
	addFlags(decryptCmd, "decrypt")

}
