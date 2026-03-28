package cmd

import (
	"fmt"
	"strconv"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

type railFenceFactory struct {
	key int
}

func (rF *railFenceFactory) name() string {
	return "railfence"
}

func (rF *railFenceFactory) parseKey(keyStr string) error {
	key, err := strconv.Atoi(keyStr)
	if err != nil {
		return err
	} else if key < 1 {
		return fmt.Errorf("key must be >= 1")
	}
	rF.key = key

	return nil
}

func (rF *railFenceFactory) newCipher(blockSize int) (ciphers.BlockCipher, error) {
	return ciphers.NewRailFenceCipher(rF.key, blockSize)
}
