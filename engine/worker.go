package engine

import (
	"fmt"
	"os"
	"sync"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

type Job struct {
	Offset int64
}

func NewJob(offset int64) Job {
	return Job{Offset: offset}
}

func Worker(workerID int, blockCipher ciphers.BlockCipher, mode ciphers.Mode, inFile *os.File, outFile *os.File, jobs <-chan Job, errors chan<- error, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	src, dst := blockCipher.GetBuffers(workerID)
	for job := range jobs {
		if _, err := inFile.ReadAt(src, job.Offset); err != nil {
			errors <- fmt.Errorf("worker %d block read error at %d: %w", workerID, job.Offset, err)
		}

		switch mode {
		case ciphers.Encrypt:
			if err := blockCipher.EncryptBlock(dst, src); err != nil {
				errors <- fmt.Errorf("worker %d block encrypt error at %d: %w", workerID, job.Offset, err)
			}

		case ciphers.Decrypt:
			if err := blockCipher.DecryptBlock(dst, src); err != nil {
				errors <- fmt.Errorf("worker %d block decrypt error at %d: %w", workerID, job.Offset, err)
			}
		}

		if _, err := outFile.WriteAt(dst, job.Offset); err != nil {
			errors <- fmt.Errorf("worker %d block write error at %d: %w", workerID, job.Offset, err)
		}
	}
}
