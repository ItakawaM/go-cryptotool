package cmd

import (
	"fmt"
	"strconv"

	"github.com/ItakawaM/arcipher/ciphers"
)

type railFenceFactory struct {
	key int
}

func (rff *railFenceFactory) name() string {
	return "railfence"
}

func (rff *railFenceFactory) parseKey(keyStr string) error {
	key, err := strconv.Atoi(keyStr)
	if err != nil {
		return err
	} else if key < 1 {
		return fmt.Errorf("key must be >= 1")
	}
	rff.key = key

	return nil
}

func (rff *railFenceFactory) newCipher(blockSize int) (ciphers.BlockCipher, error) {
	return ciphers.NewRailFenceCipher(&ciphers.RailFenceKey{
		Key:               rff.key,
		PermutationLength: blockSize,
	})
}
