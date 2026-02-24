package engine

import (
	"os"
	"sync"

	"github.com/ItakawaM/go-cryptotool/ciphers"
	"github.com/ItakawaM/go-cryptotool/ciphers/padding"
)

func ProcessFile(blockCipher ciphers.BlockCipher, mode ciphers.Mode, inFilePath, outFilePath string) error {
	blockSize := int64(blockCipher.GetBlockSize())

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

	fullBlocks := fileSize / blockSize
	remainder := fileSize % blockSize
	if err := outFile.Truncate(fileSize); err != nil {
		return err
	}

	numWorkers := blockCipher.GetNumWorkers()
	jobs := make(chan Job, numWorkers)
	errors := make(chan error, numWorkers)
	var waitGroup sync.WaitGroup

	for i := range numWorkers {
		waitGroup.Add(1)
		go Worker(i, blockCipher, mode, inFile, outFile, jobs, errors, &waitGroup)
	}

	for offset := int64(0); offset < fullBlocks*blockSize; offset += blockSize {
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

	src, dst := blockCipher.GetBuffers(0)
	switch mode {
	case ciphers.Encrypt:
		// Padding last block
		if _, err := inFile.ReadAt(src[:remainder], fullBlocks*blockSize); err != nil {
			return err
		}
		src = padding.PKCS7Pad(src[:remainder], int(blockSize))

		if err := blockCipher.EncryptBlock(dst, src); err != nil {
			return err
		}

		if _, err := outFile.WriteAt(dst, fullBlocks*blockSize); err != nil {
			return err
		}

	case ciphers.Decrypt:
		// This block is already decrypted
		if _, err := outFile.ReadAt(src, (fullBlocks-1)*blockSize); err != nil {
			return err
		}

		// Verify pad
		src, err = padding.PKCS7Unpad(src, int(blockSize))
		if err != nil {
			return err
		}

		if err := outFile.Truncate((fullBlocks-1)*blockSize + int64(len(src))); err != nil {
			return err
		}
	}

	return nil
}
