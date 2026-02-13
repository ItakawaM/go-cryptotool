package ciphers

const DefaultBlockSize int64 = 4 * 1024 * 1024

type BlockCipher interface {
	EncryptBlock([]byte) error
	DecryptBlock([]byte) error
}
