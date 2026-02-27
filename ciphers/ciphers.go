package ciphers

type CipherMode int8

const (
	Encrypt CipherMode = iota
	Decrypt
)

func (mode CipherMode) String() string {
	if mode == Encrypt {
		return "encrypt"
	}
	return "decrypt"
}

type BlockCipher interface {
	IsInPlace() bool
	EncryptBlock(dst []byte, src []byte) error
	DecryptBlock(dst []byte, src []byte) error
}
