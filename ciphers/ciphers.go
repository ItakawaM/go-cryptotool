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
	EncryptBlock([]byte, []byte) error
	DecryptBlock([]byte, []byte) error
}
