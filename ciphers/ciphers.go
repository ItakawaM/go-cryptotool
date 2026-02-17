package ciphers

type Mode int

const (
	Encrypt Mode = iota
	Decrypt
)

func (mode Mode) ToString() string {
	if mode == Encrypt {
		return "encrypt"
	}
	return "decrypt"
}

type BlockCipher interface {
	GetBuffers(workerID int) ([]byte, []byte)
	GetBlockSize() int
	GetNumWorkers() int
	EncryptBlock(dst []byte, src []byte) error
	DecryptBlock(dst []byte, src []byte) error
}

type PermutationCipher interface {
	BuildPermutationTable()
}
