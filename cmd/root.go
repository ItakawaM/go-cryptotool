package cmd

import (
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

type blockCipherParams struct {
	blockSize int
	numCPU    int
}

func addFlags(command *cobra.Command, params *blockCipherParams) {
	command.Flags().IntVarP(&params.blockSize, "block", "b", 64, "Block size (KB): 16 32 64 128 256 512 1024 2048 4096 8192 16384")
	command.Flags().IntVarP(&params.numCPU, "threads", "t", runtime.NumCPU()/2, "Amount of threads to be used")
}

var isVerbose bool
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
