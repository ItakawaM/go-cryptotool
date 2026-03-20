package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

type blockCipherParams struct {
	blockSize int
	numCPU    int
}

var isVerbose bool

func fileExists(filepath string) bool {
	if _, err := os.Stat(filepath); err == nil {
		return true
	}

	return false
}

func (params *blockCipherParams) parseSourceMessageParams(command *cobra.Command) error {
	if command.Flags().Changed("block") {
		return fmt.Errorf("--block can only be used when processing files")
	}

	if command.Flags().Changed("threads") {
		return fmt.Errorf("--threads can only be used when processing files")
	}

	return nil
}

func (params *blockCipherParams) parseSourceFileParams() error {
	if params.blockSize <= 0 {
		return fmt.Errorf("invalid block size: %d", params.blockSize)
	}

	if params.numCPU <= 0 {
		return fmt.Errorf("invalid thread count: %d", params.numCPU)
	} else if params.numCPU > runtime.NumCPU() {
		params.numCPU = runtime.NumCPU()
	}

	return nil
}

func (params *blockCipherParams) addFlags(command *cobra.Command) {
	command.Flags().IntVarP(&params.blockSize, "block", "b", 64, "Block size (KB)")
	command.Flags().IntVarP(&params.numCPU, "threads", "t", runtime.NumCPU()/2, "Amount of threads to be used")
}
