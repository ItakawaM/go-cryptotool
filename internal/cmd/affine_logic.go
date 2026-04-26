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

type affineParams struct {
	matrixKey  *ciphers.AffineKey
	isTemplate bool
	blockCipherParams
}

func affinePreRunE(command *cobra.Command, args []string, params *affineParams) error {
	switch len(args) {
	case 2:
		if !fileExists(args[0]) || !strings.HasSuffix(args[0], ".json") {
			return fmt.Errorf("invalid key file provided: %s", args[0])
		}

		key, err := loadJsonKey[ciphers.AffineKey](args[0])
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

		key, err := loadJsonKey[ciphers.AffineKey](args[0])
		if err != nil {
			return err
		}
		params.matrixKey = key

		return params.parseSourceFileParams()
	}

	return nil
}

func affineRunE(command *cobra.Command, args []string, params *affineParams, mode ciphers.CipherMode) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("affine %s", mode))()
	}

	switch len(args) {
	case 2:
		affineCipher, affineErr := ciphers.NewAffineCipher(params.matrixKey)
		if affineErr != nil {
			return affineErr
		}

		message := args[1]
		src := []byte(message)

		var err error
		switch mode {
		case ciphers.Encrypt:
			err = affineCipher.EncryptBlock(src, src)
		case ciphers.Decrypt:
			err = affineCipher.DecryptBlock(src, src)
		}
		if err != nil {
			return err
		}

		command.Printf("'%s'", string(src))

	case 3:
		blockSizeBytes := params.blockSize * 1024
		affineCipher, cardanErr := ciphers.NewAffineCipher(params.matrixKey)
		if cardanErr != nil {
			return cardanErr
		}

		inFilePath := args[1]
		outFilePath := args[2]

		return engine.NewBlockEngine(blockSizeBytes, params.numCPU).ProcessFile(affineCipher, mode, inFilePath, outFilePath)
	}

	return nil
}

func affineGenerateKeyPreRunE(args []string, params *affineParams) error {
	matrixSize, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	params.blockSize = matrixSize

	if params.blockSize <= 0 {
		return fmt.Errorf("invalid size provided: %d", params.blockSize)
	}

	return nil
}

func affineGenerateKeyRunE(command *cobra.Command, args []string, params *affineParams) error {
	if isVerbose {
		defer benchmark.MeasurePerformance("affine generate-key")()
	}

	outFile, err := os.Create(args[1])
	if err != nil {
		return err
	}
	defer outFile.Close()

	var jsonData []byte
	if params.isTemplate {
		matrixKeyTemplate := make([][]int, params.blockSize)
		for i := range params.blockSize {
			matrixKeyTemplate[i] = make([]int, params.blockSize)
		}
		vectorKeyTemplate := make([]int, params.blockSize)

		jsonData, err = json.Marshal(&ciphers.AffineKey{
			MatrixKey: matrixKeyTemplate,
			VectorKey: vectorKeyTemplate,
		})
		if err != nil {
			return err
		}

	} else {
		key, err := ciphers.GenerateAffineKey(params.blockSize)
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
