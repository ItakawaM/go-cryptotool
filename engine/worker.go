package engine

import (
	"io"
	"log"
	"os"
	"sync"

	"github.com/ItakawaM/go-cryptotool/ciphers"
)

type Job struct {
	Offset int64
	Size   int64
}

func NewJob(offset int64, size int64) Job {
	if size <= 0 {
		log.Fatalf("Incorrect parameters for NewJob provided: Offset[%d], Size[%d]", offset, size)
	}

	return Job{Offset: offset, Size: size}
}

func Worker(mode string, blockCipher ciphers.BlockCipher, inFile *os.File, outfile *os.File, jobs <-chan Job, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	for job := range jobs {
		buffer := make([]byte, job.Size)

		if _, err := inFile.ReadAt(buffer, job.Offset); err != nil && err != io.EOF {
			log.Fatalln("Reading block error: ", err)
		}

		switch mode {
		case "encrypt":
			if err := blockCipher.EncryptBlock(buffer); err != nil {
				log.Fatalln("Encrypting block error: ", err)
			}

		case "decrypt":
			if err := blockCipher.DecryptBlock(buffer); err != nil {
				log.Fatalln("Decrypting block error: ", err)
			}
		}

		if _, err := outfile.WriteAt(buffer, job.Offset); err != nil {
			log.Fatalln("Writing block error: ", err)
		}
	}
}
