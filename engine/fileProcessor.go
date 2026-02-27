package engine

import (
	"os"
	"sync"

	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/ciphers/padding"
)

type BlockEngine struct {
	mode      ciphers.Mode
	blockSize int
	numCpu    int
}

func NewBlockEngine(mode ciphers.Mode, blockSize int, numCpu int) *BlockEngine {
	return &BlockEngine{
		mode:      mode,
		blockSize: blockSize,
		numCpu:    numCpu,
	}
}

func (be *BlockEngine) ProcessFile(blockCipher ciphers.BlockCipher, inFilePath, outFilePath string) error {
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

	fullBlocks := fileSize / int64(be.blockSize)
	remainder := fileSize % int64(be.blockSize)
	if err := outFile.Truncate(fileSize); err != nil {
		return err
	}

	jobs := make(chan Job, be.numCpu)
	errors := make(chan error, be.numCpu)
	var waitGroup sync.WaitGroup

	var buffers [][]byte
	if blockCipher.IsInPlace() {
		buffers = make([][]byte, be.numCpu)
	} else {
		buffers = make([][]byte, be.numCpu*2)
	}
	for index := range buffers {
		buffers[index] = make([]byte, be.blockSize)
	}

	for i := range be.numCpu {
		waitGroup.Add(1)
		worker := NewWorker(i, buffers, blockCipher, be.mode, inFile, outFile, jobs, errors, &waitGroup)

		go worker.Start()
	}

	for offset := int64(0); offset < fullBlocks*int64(be.blockSize); offset += int64(be.blockSize) {
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

	src, dst := buffers[0], buffers[1]
	switch be.mode {
	case ciphers.Encrypt:
		// Padding last block
		if _, err := inFile.ReadAt(src[:remainder], fullBlocks*int64(be.blockSize)); err != nil {
			return err
		}
		src = padding.PKCS7Pad(src[:remainder], int(be.blockSize))

		if err := blockCipher.EncryptBlock(dst, src); err != nil {
			return err
		}

		if _, err := outFile.WriteAt(dst, fullBlocks*int64(be.blockSize)); err != nil {
			return err
		}

	case ciphers.Decrypt:
		// This block is already decrypted
		if _, err := outFile.ReadAt(src, (fullBlocks-1)*int64(be.blockSize)); err != nil {
			return err
		}

		// Verify pad
		src, err = padding.PKCS7Unpad(src, int(be.blockSize))
		if err != nil {
			return err
		}

		if err := outFile.Truncate((fullBlocks-1)*int64(be.blockSize) + int64(len(src))); err != nil {
			return err
		}
	}

	return nil
}
