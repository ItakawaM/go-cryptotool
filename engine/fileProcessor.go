package engine

import (
	"io"
	"os"
	"runtime"
	"sync"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

func ProcessFile(mode string, inFilePath, outFilePath string, blockCipher ciphers.BlockCipher) error {
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
	if fileSize < ciphers.DefaultBlockSize {
		buffer := make([]byte, fileSize)
		if _, err := inFile.Read(buffer); err != nil && err != io.EOF {
			return err
		}

		switch mode {
		case "encrypt":
			if err := blockCipher.EncryptBlock(buffer); err != nil {
				return err
			}

		case "decrypt":
			if err := blockCipher.DecryptBlock(buffer); err != nil {
				return err
			}
		}

		_, err := outFile.WriteAt(buffer, 0)
		return err
	}

	numWorkers := runtime.NumCPU()
	jobs := make(chan Job, numWorkers)
	var waitGroup sync.WaitGroup

	for range numWorkers {
		waitGroup.Add(1)
		go Worker(mode, blockCipher, inFile, outFile, jobs, &waitGroup)
	}

	for offset := int64(0); offset < fileSize; offset += ciphers.DefaultBlockSize {
		size := ciphers.DefaultBlockSize
		if offset+ciphers.DefaultBlockSize > fileSize {
			size = fileSize - offset
		}

		jobs <- NewJob(offset, size)
	}

	close(jobs)
	waitGroup.Wait()

	return nil
}
