package cmd

import (
	"fmt"
	"runtime"
	"slices"

	"github.com/spf13/cobra"
)

type BlockCipherParams struct {
	blockSize  int
	numCPU     int
	notPadding bool
	mode       WorkingMode
}

type WorkingMode int8

const (
	ModeMessage WorkingMode = iota
	ModeFiles
)

func modeFromArgs(args []string) (WorkingMode, error) {
	switch len(args) {
	case 2:
		return ModeMessage, nil
	case 3:
		return ModeFiles, nil
	default:
		return 0, fmt.Errorf("invalid number of arguments")
	}
}

var isVerbose bool
var allowedBlockSizes = []int{
	16, 32, 64, 128, 256, 512,
	1024, 2048, 4096, 8192, 16384,
}

func (params *BlockCipherParams) parseModeMessageArgs(command *cobra.Command) error {
	if command.Flags().Changed("block") {
		return fmt.Errorf("--block can only be used when processing files")
	}

	if command.Flags().Changed("threads") {
		return fmt.Errorf("--threads can only be used when processing files")
	}

	if command.Flags().Changed("padding") {
		return fmt.Errorf("--padding can only be used when processing files")
	}

	return nil
}

func (params *BlockCipherParams) parseModeFilesArgs() error {
	if !slices.Contains(allowedBlockSizes, params.blockSize) {
		return fmt.Errorf("invalid block size: %d", params.blockSize)
	}

	if params.numCPU <= 0 {
		return fmt.Errorf("invalid thread count: %d", params.numCPU)
	} else if params.numCPU > runtime.NumCPU() {
		params.numCPU = runtime.NumCPU()
	}

	return nil
}

func (params *BlockCipherParams) addFlags(command *cobra.Command) {
	command.Flags().IntVarP(&params.blockSize, "block", "b", 64, "Block size (KB): 16 32 64 128 256 512 1024 2048 4096 8192 16384")
	command.Flags().IntVarP(&params.numCPU, "threads", "t", runtime.NumCPU()/2, "Amount of threads to be used")
	command.Flags().BoolVarP(&params.notPadding, "short", "s", false, "No padding mode")
}
