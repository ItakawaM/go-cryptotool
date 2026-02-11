package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	ciphers "github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/spf13/cobra"
)

var (
	message  string
	filename string
	key      int
)

// railfenceCmd represents the railfence command.
var railfenceCmd = &cobra.Command{
	Use:   "railfence",
	Short: "Encrypt or decrypt data using the Rail Fence cipher",
	// Thanks, ChatGPT
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

  Encrypt text:
    1. cipher railfence --encrypt --key 3 --message "Hello World"

    2. echo "Hello World" | cipher railfence --encrypt --key 3
	
  Encrypt a file:
    1. cipher railfence --encrypt --key 5 --file input.txt

Notes:

  • The key must be >= 1
  • Larger keys increase computation time
  • For very large files, performance depends on system memory
`,
	Run: func(cmd *cobra.Command, args []string) {
		startTime := time.Now()

		stat, _ := os.Stdin.Stat()
		if message == "" && filename == "" && (stat.Mode()&os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			var builder strings.Builder
			for scanner.Scan() {
				builder.WriteString(scanner.Text())
			}

			message = builder.String()
		}

		if message == "" && filename == "" {
			fmt.Println("Please provide an input to encrypt!")
			os.Exit(1)
		}

		if key <= 0 {
			fmt.Printf("Invalid key provided: [%d] is not viable", key)
			os.Exit(1)
		}

		if message != "" {
			encryptedMessage := ciphers.RailFenceEncryptMessage(message, key)
			fmt.Println(encryptedMessage)
		} else {
			if err := ciphers.RailFenceEncryptFile(filename, key); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		elapsed := time.Since(startTime)
		fmt.Printf("Encrypting Took: %s", elapsed)
	},
}

func init() {
	rootCmd.AddCommand(railfenceCmd)
	railfenceCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringVarP(&message, "message", "m", "", "Message to encrypt")
	encryptCmd.Flags().StringVarP(&filename, "file", "f", "", "File to encrypt")
	encryptCmd.Flags().IntVarP(&key, "key", "k", 0, "Key to use")

	encryptCmd.MarkFlagRequired("key")

	encryptCmd.MarkFlagsMutuallyExclusive("file", "message")
}
