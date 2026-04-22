package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/ItakawaM/arcipher/ciphers"
	"github.com/spf13/cobra"
)

type hillParams struct {
	matrixKey  *ciphers.HillKey
	isTemplate bool
	blockCipherParams
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
