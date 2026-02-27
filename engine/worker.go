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

type Worker struct {
	id        int
	src       []byte
	dst       []byte
	cipher    ciphers.BlockCipher
	mode      ciphers.CipherMode
	inFile    *os.File
	outFile   *os.File
	jobs      <-chan Job
	errors    chan<- error
	waitGroup *sync.WaitGroup
}

func NewWorker(workerID int, buffers [][]byte, blockCipher ciphers.BlockCipher, mode ciphers.CipherMode, inFile *os.File, outFile *os.File, jobs <-chan Job, errors chan<- error, waitGroup *sync.WaitGroup) *Worker {
	var src, dst []byte
	if blockCipher.IsInPlace() {
		src, dst = buffers[workerID], buffers[workerID]
	} else {
		src, dst = buffers[workerID*2], buffers[workerID*2+1]
	}

	return &Worker{
		id:        workerID,
		src:       src,
		dst:       dst,
		cipher:    blockCipher,
		mode:      mode,
		inFile:    inFile,
		outFile:   outFile,
		jobs:      jobs,
		errors:    errors,
		waitGroup: waitGroup,
	}
}

func (w *Worker) Start() {
	defer w.waitGroup.Done()

	for job := range w.jobs {
		if _, err := w.inFile.ReadAt(w.src, job.Offset); err != nil {
			w.errors <- fmt.Errorf("worker %d block read error at %d: %w", w.id, job.Offset, err)
			return
		}

		switch w.mode {
		case ciphers.Encrypt:
			if err := w.cipher.EncryptBlock(w.dst, w.src); err != nil {
				w.errors <- fmt.Errorf("worker %d block encrypt error at %d: %w", w.id, job.Offset, err)
				return
			}

		case ciphers.Decrypt:
			if err := w.cipher.DecryptBlock(w.dst, w.src); err != nil {
				w.errors <- fmt.Errorf("worker %d block decrypt error at %d: %w", w.id, job.Offset, err)
				return
			}
		}

		if _, err := w.outFile.WriteAt(w.dst, job.Offset); err != nil {
			w.errors <- fmt.Errorf("worker %d block write error at %d: %w", w.id, job.Offset, err)
			return
		}
	}
}
