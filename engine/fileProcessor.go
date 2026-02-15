package engine

import (
	"io"
	"os"
	"runtime"
	"sync"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

func ProcessFile(mode ciphers.Mode, inFilePath, outFilePath string, blockCipher ciphers.BlockCipher, blockSize int64) error {
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

	if err := outFile.Truncate(fileSize); err != nil {
		return err
	}

	// For small files
	if fileSize < blockSize {
		readBuffer := make([]byte, fileSize)
		buffer := make([]byte, fileSize)

		if _, err := inFile.Read(readBuffer); err != nil && err != io.EOF {
			return err
		}

		switch mode {
		case ciphers.Encrypt:
			if err := blockCipher.EncryptBlock(readBuffer, buffer); err != nil {
				return err
			}

		case ciphers.Decrypt:
			if err := blockCipher.DecryptBlock(readBuffer, buffer); err != nil {
				return err
			}
		}

		_, err := outFile.WriteAt(readBuffer, 0)
		return err
	}

	numWorkers := runtime.NumCPU()
	jobs := make(chan Job, numWorkers)
	var waitGroup sync.WaitGroup

	buffers := make([][]byte, numWorkers*2)
	for i := range numWorkers {
		buffers[i*2] = make([]byte, blockSize)
		buffers[i*2+1] = make([]byte, blockSize)
	}

	for i := range numWorkers {
		waitGroup.Add(1)
		go Worker(mode, blockCipher, inFile, outFile, jobs, &waitGroup, buffers, i)
	}

	for offset := int64(0); offset < fileSize; offset += blockSize {
		size := blockSize
		if offset+blockSize > fileSize {
			size = fileSize - offset
		}

		jobs <- NewJob(offset, size)
	}

	close(jobs)
	waitGroup.Wait()

	return nil
}
