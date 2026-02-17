package engine

import (
	"log"
	"os"
	"sync"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

type Job struct {
	Offset int64
}

func NewJob(offset int64, size int64) Job {
	return Job{Offset: offset}
}

func Worker(workerID int, blockCipher ciphers.BlockCipher, mode ciphers.Mode, inFile *os.File, outFile *os.File, jobs <-chan Job, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	src, dst := blockCipher.GetBuffers(workerID)
	for job := range jobs {
		if _, err := inFile.ReadAt(src, job.Offset); err != nil {
			log.Fatalln("Reading block error: ", err)
		}

		switch mode {
		case ciphers.Encrypt:
			if err := blockCipher.EncryptBlock(dst, src); err != nil {
				log.Fatalln("Encrypting block error: ", err)
			}

		case ciphers.Decrypt:
			if err := blockCipher.DecryptBlock(dst, src); err != nil {
				log.Fatalln("Decrypting block error: ", err)
			}
		}

		if _, err := outFile.WriteAt(dst, job.Offset); err != nil {
			log.Fatalln("Writing block error: ", err)
		}
	}
}
