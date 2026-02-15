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

func Worker(mode ciphers.Mode, blockCipher ciphers.BlockCipher, inFile *os.File, outfile *os.File, jobs <-chan Job, waitGroup *sync.WaitGroup, buffers [][]byte, id int) {
	defer waitGroup.Done()

	for job := range jobs {
		inBuffer := buffers[id*2][:job.Size]
		helperBuffer := buffers[id*2+1][:job.Size]

		if _, err := inFile.ReadAt(inBuffer, job.Offset); err != nil && err != io.EOF {
			log.Fatalln("Reading block error: ", err)
		}

		switch mode {
		case ciphers.Encrypt:
			if err := blockCipher.EncryptBlock(inBuffer, helperBuffer); err != nil {
				log.Fatalln("Encrypting block error: ", err)
			}

		case ciphers.Decrypt:
			if err := blockCipher.DecryptBlock(inBuffer, helperBuffer); err != nil {
				log.Fatalln("Decrypting block error: ", err)
			}
		}

		if _, err := outfile.WriteAt(inBuffer, job.Offset); err != nil {
			log.Fatalln("Writing block error: ", err)
		}
	}
}
