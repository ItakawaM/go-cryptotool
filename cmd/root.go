package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "go-cryptotool",
	Short: "Classic encryption ciphers in Go!",
	Long: `ItakawaM
	
	Work In Progress`, // TODO: Create a nice Long description

}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&isVerbose, "verbose", "v", false, "Displays additional info")

	rootCmd.AddCommand(NewRailFenceCommand(), NewCaesarCommand())
}
