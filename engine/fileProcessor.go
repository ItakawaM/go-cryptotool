package engine

import (
	"io"
	"os"
	"sync"

	"github.com/ItakawaM/go-cryptotool/ciphers"
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

	// For small files
	if fileSize < int64(blockCipher.GetBlockSize()) {
		src := make([]byte, blockSize)
		dst := make([]byte, blockSize)

		if _, err := inFile.Read(src); err != nil && err != io.EOF {
			return err
		}

		switch mode {
		case ciphers.Encrypt:
			if err := blockCipher.EncryptBlock(dst, src); err != nil {
				return err
			}

		case ciphers.Decrypt:
			if err := blockCipher.DecryptBlock(dst, src); err != nil {
				return err
			}
		}

		_, err := outFile.WriteAt(dst, 0)
		return err
	}

	fullBlocks := fileSize / blockSize
	remainder := fileSize % blockSize
	if err := outFile.Truncate(fileSize); err != nil {
		return err
	}

	numWorkers := blockCipher.GetNumWorkers()
	jobs := make(chan Job, numWorkers)
	var waitGroup sync.WaitGroup

	for i := range numWorkers {
		waitGroup.Add(1)
		go Worker(i, blockCipher, mode, inFile, outFile, jobs, &waitGroup)
	}

	for offset := int64(0); offset < fullBlocks*blockSize; offset += blockSize {
		jobs <- NewJob(offset, blockSize)
	}

	close(jobs)
	waitGroup.Wait()

	if remainder > 0 {
		src := make([]byte, blockSize)
		dst := make([]byte, blockSize)

		if _, err := inFile.ReadAt(src[:remainder], fullBlocks*blockSize); err != nil {
			return err
		}

		switch mode {
		case ciphers.Encrypt:
			if err := blockCipher.EncryptBlock(dst, src); err != nil {
				return err
			}

		case ciphers.Decrypt:
			if err := blockCipher.DecryptBlock(dst, src); err != nil {
				return err
			}
		}

		if _, err := outFile.WriteAt(dst, fullBlocks*blockSize); err != nil {
			return err
		}
	}

	return nil
}
