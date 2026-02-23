package ciphers

type CaesarCipher struct {
	Key       byte
	BlockSize int
	Buffers   [][]byte
	// TODO: Think of a better way to structure
	// TODO: Implement different languages?
}

func NewCaesarCipher(key byte, blockSize int, numCPU int) *CaesarCipher {
	buffers := make([][]byte, numCPU*2)
	for i := range buffers {
		buffers[i] = make([]byte, blockSize)
	}

	return &CaesarCipher{
		Key:       key,
		BlockSize: blockSize,
		Buffers:   buffers,
	}
}

func (cc *CaesarCipher) GetBuffers(workerID int) ([]byte, []byte) {
	return cc.Buffers[workerID*2], cc.Buffers[workerID*2+1]
}

func (cc *CaesarCipher) GetBlockSize() int {
	return cc.BlockSize
}

func (cc *CaesarCipher) GetNumWorkers() int {
	return len(cc.Buffers) / 2
}

func (cc *CaesarCipher) EncryptBlock(dst []byte, src []byte) error {
	if cc.Key == 0 {
		copy(dst, src)
		return nil
	}

	for index, char := range src {
		if char >= 0x41 && char <= 0x5A {
			dst[index] = 0x41 + (char-0x41+cc.Key)%26
		} else if char >= 0x61 && char <= 0x7A {
			dst[index] = 0x61 + (char-0x61+cc.Key)%26
		} else {
			dst[index] = char
		}
	}

	return nil
}
func (cc *CaesarCipher) DecryptBlock(dst []byte, src []byte) error {
	if cc.Key == 0 {
		copy(dst, src)
		return nil
	}

	for index, char := range src {
		if char >= 0x41 && char <= 0x5A {
			dst[index] = 0x41 + ((char-0x41-cc.Key)+26)%26
		} else if char >= 0x61 && char <= 0x7A {
			dst[index] = 0x61 + ((char-0x61-cc.Key)+26)%26
		} else {
			dst[index] = char
		}
	}

	return nil
}
