package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ItakawaM/arcipher/ciphers"
	"github.com/ItakawaM/arcipher/internal/benchmark"
	"github.com/ItakawaM/arcipher/internal/engine"
	"github.com/spf13/cobra"
)

type hillParams struct {
	matrixKey  *ciphers.HillKey
	isTemplate bool
	blockCipherParams
}

func loadHillKey(path string) (*ciphers.HillKey, error) {
	// Unionize with loadCardanKey?
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var key ciphers.HillKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, err
	}

	return &key, nil
}

func hillPreRunE(command *cobra.Command, args []string, params *hillParams) error {
	switch len(args) {
	case 2:
		if !fileExists(args[0]) || !strings.HasSuffix(args[0], ".json") {
			return fmt.Errorf("invalid key file provided: %s", args[0])
		}

		key, err := loadHillKey(args[0])
		if err != nil {
			return err
		}
		params.matrixKey = key

		return params.parseSourceMessageParams(command)

	case 3:
		if !fileExists(args[0]) || !strings.HasSuffix(args[0], ".json") {
			return fmt.Errorf("invalid key file provided: %s", args[0])
		}
		if !fileExists(args[1]) {
			return fmt.Errorf("provided input file does not exist: %s", args[1])
		}

		key, err := loadHillKey(args[0])
		if err != nil {
			return err
		}
		params.matrixKey = key

		return params.parseSourceFileParams()
	}

	return nil
}

func hillRunE(command *cobra.Command, args []string, params *hillParams, mode ciphers.CipherMode) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("hill %s", mode))()
	}

	switch len(args) {
	case 2:
		hillCipher, hillErr := ciphers.NewHillCipher(params.matrixKey)
		if hillErr != nil {
			return hillErr
		}

		message := args[1]
		src := []byte(message)

		var err error
		switch mode {
		case ciphers.Encrypt:
			err = hillCipher.EncryptBlock(src, src)
		case ciphers.Decrypt:
			err = hillCipher.DecryptBlock(src, src)
		}
		if err != nil {
			return err
		}

		command.Printf("'%s'", string(src))

	case 3:
		blockSizeBytes := params.blockSize * 1024
		hillCipher, cardanErr := ciphers.NewHillCipher(params.matrixKey)
		if cardanErr != nil {
			return cardanErr
		}

		inFilePath := args[1]
		outFilePath := args[2]
		command.Println(blockSizeBytes)

		return engine.NewBlockEngine(blockSizeBytes, params.numCPU).ProcessFile(hillCipher, mode, inFilePath, outFilePath)
	}

	return nil
}

func hillGenerateKeyPreRunE(args []string, params *hillParams) error {
	matrixSize, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	params.blockSize = matrixSize

	if params.blockSize <= 1 {
		return fmt.Errorf("invalid size provided: %d", params.blockSize)
	}

	return nil
}

func hillGenerateKeyRunE(command *cobra.Command, args []string, params *hillParams) error {
	if isVerbose {
		defer benchmark.MeasurePerformance("hill generate-key")()
	}

	outFile, err := os.Create(args[1])
	if err != nil {
		return err
	}
	defer outFile.Close()

	var jsonData []byte
	if params.isTemplate {
		keyTemplate := make([][]int, params.blockSize)
		for i := range params.blockSize {
			keyTemplate[i] = make([]int, params.blockSize)
		}

		jsonData, err = json.Marshal(&ciphers.HillKey{
			Key: keyTemplate,
		})
		if err != nil {
			return err
		}

	} else {
		key, err := ciphers.GenerateHillKey(params.blockSize)
		if err != nil {
			return err
		}

		jsonData, err = json.Marshal(key)
		if err != nil {
			return err
		}
	}

	if _, err := outFile.Write(jsonData); err != nil {
		return err
	}

	command.Printf("Key written to %s\n", args[1])
	return nil
}
