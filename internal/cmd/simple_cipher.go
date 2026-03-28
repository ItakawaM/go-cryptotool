package cmd

import (
	"bytes"
	"fmt"

	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/internal/benchmark"
	"github.com/ItakawaM/go-cryptotool/internal/engine"
	"github.com/spf13/cobra"
)

type cipherFactory interface {
	name() string
	parseKey(keyStr string) error
	newCipher(blockSize int) (ciphers.BlockCipher, error)
}

func simpleCipherPreRunE(command *cobra.Command, args []string, factory cipherFactory, params *blockCipherParams) error {
	if err := factory.parseKey(args[0]); err != nil {
		return err
	}

	switch len(args[1:]) {
	case 1:
		return params.parseSourceMessageParams(command)
	case 2:
		if !fileExists(args[1]) {
			return fmt.Errorf("provided input file does not exist: %s", args[1])
		}
		return params.parseSourceFileParams()
	default:
		return fmt.Errorf("invalid working mode")
	}
}

func simpleCipherRunE(command *cobra.Command, args []string, factory cipherFactory, params *blockCipherParams, mode ciphers.CipherMode) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("%s %s", factory.name(), mode))()
	}

	switch len(args[1:]) {
	case 1:
		message := args[1]
		cipher, err := factory.newCipher(len(message))
		if err != nil {
			return err
		}

		src := []byte(message)
		dst := bytes.Clone(src)

		switch mode {
		case ciphers.Encrypt:
			err = cipher.EncryptBlock(dst, src)
		case ciphers.Decrypt:
			err = cipher.DecryptBlock(dst, src)
		}
		if err != nil {
			return err
		}

		command.Printf("'%s'", string(dst))
		return nil

	case 2:
		inFilePath, outFilePath := args[1], args[2]
		blockSizeBytes := params.blockSize * 1024
		cipher, err := factory.newCipher(blockSizeBytes)
		if err != nil {
			return err
		}
		return engine.NewBlockEngine(blockSizeBytes, params.numCPU).ProcessFile(cipher, mode, inFilePath, outFilePath)

	default:
		return fmt.Errorf("invalid amount of arguments provided")
	}
}
