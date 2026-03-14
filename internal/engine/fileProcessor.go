package engine

import (
	"fmt"
	"os"
	"sync"

	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/ciphers/padding"
)

type BlockEngine struct {
	blockSize int
	numCpu    int
}

func NewBlockEngine(blockSize int, numCpu int) *BlockEngine {
	return &BlockEngine{
		blockSize: blockSize,
		numCpu:    numCpu,
	}
}

func (blockEngine *BlockEngine) ProcessFile(blockCipher ciphers.BlockCipher, mode ciphers.CipherMode, inFilePath, outFilePath string) error {
	inFile, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	info, err := inFile.Stat()
	if err != nil {
		return err
	}
	fileSize := info.Size()

	fullBlocks := fileSize / int64(blockEngine.blockSize)
	remainder := fileSize % int64(blockEngine.blockSize)

	if mode == ciphers.Decrypt && fullBlocks < 1 {
		return fmt.Errorf("padding corruption or no padding provided for decryption")
	}

	if err := outFile.Truncate((fullBlocks + 1) * int64(blockEngine.blockSize)); err != nil {
		return err
	}

	jobs := make(chan Job, blockEngine.numCpu)
	errors := make(chan error, blockEngine.numCpu)
	var waitGroup sync.WaitGroup

	var buffers [][]byte
	if blockCipher.IsInPlace() {
		buffers = make([][]byte, blockEngine.numCpu)
	} else {
		buffers = make([][]byte, blockEngine.numCpu*2)
	}
	for index := range buffers {
		buffers[index] = make([]byte, blockEngine.blockSize)
	}

	for i := range blockEngine.numCpu {
		waitGroup.Add(1)
		worker := NewWorker(i, buffers, blockCipher, mode, inFile, outFile, jobs, errors, &waitGroup)

		go worker.Start()
	}

	for offset := int64(0); offset < fullBlocks*int64(blockEngine.blockSize); offset += int64(blockEngine.blockSize) {
		jobs <- NewJob(offset)
	}
	close(jobs)

	go func() {
		waitGroup.Wait()
		close(errors)
	}()

	for err := range errors {
		if err != nil {
			return err
		}
	}

	var src, dst []byte
	if blockCipher.IsInPlace() {
		src = buffers[0]
		dst = buffers[0]
	} else {
		src = buffers[0]
		dst = buffers[1]
	}

	switch mode {
	case ciphers.Encrypt:
		// Padding last block
		if _, err := inFile.ReadAt(src[:remainder], fullBlocks*int64(blockEngine.blockSize)); err != nil {
			return err
		}
		src = padding.Pad(src[:remainder], int(blockEngine.blockSize))

		if err := blockCipher.EncryptBlock(dst, src); err != nil {
			return err
		}

		if _, err := outFile.WriteAt(dst, fullBlocks*int64(blockEngine.blockSize)); err != nil {
			return err
		}

	case ciphers.Decrypt:
		// This block is already decrypted
		if _, err := outFile.ReadAt(src, (fullBlocks-1)*int64(blockEngine.blockSize)); err != nil {
			return err
		}

		// Verify pad
		src, err = padding.Unpad(src, int(blockEngine.blockSize))
		if err != nil {
			return err
		}

		if err := outFile.Truncate((fullBlocks-1)*int64(blockEngine.blockSize) + int64(len(src))); err != nil {
			return err
		}
	}

	return nil
}
