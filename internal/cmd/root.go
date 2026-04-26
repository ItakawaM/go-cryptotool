package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "arcipher",
	Short: "Classic encryption ciphers in Go!",
	Long: `ItakawaM

CLI tool for classical cryptography and cryptanalysis.
Provides implementations of historical ciphers with file processing and concurrent operations.
`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&isVerbose, "verbose", "v", false, "Displays additional info")

	rootCmd.AddCommand(
		NewRailFenceCommand(),
		NewCaesarCommand(),
		NewCardanCommand(),
		NewVigenereCommand(),
		NewAffineCommand(),
	)
}
