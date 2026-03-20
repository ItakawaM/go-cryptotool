package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/internal/benchmark"
	"github.com/ItakawaM/go-cryptotool/internal/engine"
	"github.com/spf13/cobra"
)

type cardanParams struct {
	gridKey *ciphers.CardanKey
	blockCipherParams
}

func loadCardanKey(path string) (*ciphers.CardanKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var key ciphers.CardanKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, err
	}

	return &key, nil
}

func calculateGridSize(gridKeyLen int) (int, error) {
	for _, candidate := range []int{
		int(math.Round(math.Sqrt(float64(4 * gridKeyLen)))),
		int(math.Round(math.Sqrt(float64(4*gridKeyLen + 1)))),
	} {
		if candidate > 0 && (candidate*candidate-candidate%2)/4 == gridKeyLen {
			return candidate, nil
		}
	}

	return 0, fmt.Errorf("key length %d does not correspond to any valid grid size", gridKeyLen)
}

func cardanPreRunE(command *cobra.Command, args []string, params *cardanParams) error {
	switch len(args) {
	case 1:
		params.blockSize = int(math.Ceil(math.Sqrt(float64(len(args[0])))))
		return params.parseSourceMessageParams(command)
	case 2:
		if !fileExists(args[0]) || !strings.HasSuffix(args[0], ".json") {
			return fmt.Errorf("invalid key file provided: %s", args[0])
		}
		params.blockSize = int(math.Ceil(math.Sqrt(float64(len(args[1])))))

		key, err := loadCardanKey(args[0])
		if err != nil {
			return err
		}
		params.gridKey = key

		return params.parseSourceMessageParams(command)

	case 3:
		if !fileExists(args[0]) || !strings.HasSuffix(args[0], ".json") {
			return fmt.Errorf("invalid key file provided: %s", args[0])
		}
		if !fileExists(args[1]) {
			return fmt.Errorf("provided input file does not exist: %s", args[1])
		}

		key, err := loadCardanKey(args[0])
		if err != nil {
			return err
		}
		gridSize, err := calculateGridSize(len(key.Key))
		if err != nil {
			return err
		}
		params.blockSize = gridSize
		params.gridKey = key

		return params.parseSourceFileParams()
	}

	return nil
}

func cardanRunE(command *cobra.Command, args []string, params *cardanParams, mode ciphers.CipherMode) error {
	if isVerbose {
		defer benchmark.MeasurePerformance(fmt.Sprintf("cardan %s", mode))()
	}

	switch len(args) {
	case 1:
		command.Println("WIP")

	case 2:
		cardanCipher, cardanErr := ciphers.NewCardanCipher(params.gridKey, params.blockSize)
		if cardanErr != nil {
			return cardanErr
		}

		src := []byte(args[1])
		src = append(src, bytes.Repeat([]byte(" "), params.blockSize*params.blockSize-len(src))...)
		dst := make([]byte, len(src))

		var err error
		switch mode {
		case ciphers.Encrypt:
			err = cardanCipher.EncryptBlock(dst, src)
		case ciphers.Decrypt:
			err = cardanCipher.DecryptBlock(dst, src)
		}
		if err != nil {
			return err
		}

		command.Println(string(dst))

	case 3:
		cardanCipher, cardanErr := ciphers.NewCardanCipher(params.gridKey, params.blockSize)
		if cardanErr != nil {
			return cardanErr
		}

		inFilePath := args[1]
		outFilePath := args[2]

		return engine.NewBlockEngine(params.blockSize*params.blockSize, params.numCPU).ProcessFile(cardanCipher, mode, inFilePath, outFilePath)
	}

	return nil
}

func cardanGenerateKeyPreRunE(args []string, params *cardanParams) error {
	gridSize, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	params.blockSize = gridSize

	if params.blockSize <= 0 {
		return fmt.Errorf("invalid size provided: %d", params.blockSize)
	}

	return nil
}

func cardanGenerateKeyRunE(command *cobra.Command, args []string, params *cardanParams) error {
	key, err := ciphers.GenerateCardanKey(params.blockSize)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(key)
	if err != nil {
		return err
	}

	outFile, err := os.Create(args[1])
	if err != nil {
		return err
	}

	if _, err := outFile.Write(jsonData); err != nil {
		return err
	}

	defer command.Printf("Key written to %s\n", args[1])
	return outFile.Close()
}
