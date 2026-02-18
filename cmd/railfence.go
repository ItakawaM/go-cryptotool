package cmd

import (
	"fmt"
	"runtime"
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
	numCPU         int
	allowedBlock   []int = []int{16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}
	isVisual       bool
)

func addFlags(command *cobra.Command, mode string) {
	command.Flags().StringVarP(&message, "message", "m", "", fmt.Sprintf("Message to %s", mode))
	command.Flags().StringVarP(&inputFilePath, "input", "i", "", fmt.Sprintf("Path to file to %s", mode))
	command.Flags().StringVarP(&outputFilePath, "output", "o", "", "Path to output file")
	command.Flags().IntVarP(&key, "key", "k", 0, "Cipher algorithm key")
	command.Flags().IntVarP(&blockSize, "block", "b", 64, "Block size (KB): 16 32 64 128 256 512 1024 2048 4096 8192 16384")
	command.Flags().IntVarP(&numCPU, "threads", "t", runtime.NumCPU()/2, "Amount of threads to be used")

	command.MarkFlagRequired("key")
	command.MarkFlagsRequiredTogether("input", "output")
	command.MarkFlagsMutuallyExclusive("message", "input")
	command.MarkFlagsMutuallyExclusive("message", "block")
	command.MarkFlagsMutuallyExclusive("message", "threads")
}

func railfencePreRunE() error {
	if key < 1 {
		return fmt.Errorf("provided --key must be >=1")
	}

	if !slices.Contains(allowedBlock, blockSize) {
		return fmt.Errorf("Provided block size[%d] is not viable!", blockSize)
	}
	if numCPU <= 0 {
		return fmt.Errorf("Incorrect amount of threads[%d] provided!", numCPU)
	} else if numCPU > runtime.NumCPU() {
		numCPU = runtime.NumCPU()
	}

	blockSize *= 1024 // Convert to KB

	return nil
}

// Logic
func railfenceRunE(mode ciphers.Mode) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("railfence %s", mode))()
	}

	if message != "" {
		railFenceCipher := ciphers.NewRailFenceCipher(key, len(message), 1)
		railFenceCipher.BuildPermutationTable()
		src := []byte(message)
		dst := make([]byte, len(src))

		if isVisual {
			railFenceCipher.Visualize(message)
		}

		var err error
		switch mode {
		case ciphers.Encrypt:
			err = railFenceCipher.EncryptBlock(dst, src)
		case ciphers.Decrypt:
			err = railFenceCipher.DecryptBlock(dst, src)
		}
		if err != nil {
			return err
		}

		fmt.Println(string(dst))
	} else {
		railFenceCipher := ciphers.NewRailFenceCipher(key, blockSize, numCPU)
		railFenceCipher.BuildPermutationTable()
		err := engine.ProcessFile(railFenceCipher, mode, inputFilePath, outputFilePath)
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
	encryptCmd.Flags().BoolVarP(&isVisual, "print", "p", false, "Prints out the way a message is encrypted")
	encryptCmd.MarkFlagsMutuallyExclusive("input", "print")

	addFlags(decryptCmd, "decrypt")

}
