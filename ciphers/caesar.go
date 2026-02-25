package ciphers

type CaesarCipher struct {
	Key               byte
	BlockSize         int
	Buffers           [][]byte
	SubstitutionTable [256]byte
	ReverseTable      [256]byte
}

func NewCaesarCipher(key byte, blockSize int, numCPU int) *CaesarCipher {
	buffers := make([][]byte, numCPU)
	for i := range buffers {
		buffers[i] = make([]byte, blockSize)
	}

	var substitutionTable [256]byte
	var reverseTable [256]byte
	for char := range byte(255) {
		if char >= 'a' && char <= 'z' {
			newChar := 'a' + (char-'a'+key)%26
			substitutionTable[char] = newChar
			reverseTable[newChar] = char
		} else if char >= 'A' && char <= 'Z' {
			newChar := 'A' + (char-'A'+key)%26
			substitutionTable[char] = newChar
			reverseTable[newChar] = char
		} else {
			substitutionTable[char] = char
			reverseTable[char] = char
		}
	}

	return &CaesarCipher{
		Key:               key,
		BlockSize:         blockSize,
		Buffers:           buffers,
		SubstitutionTable: substitutionTable,
		ReverseTable:      reverseTable,
	}
}

func (cc *CaesarCipher) GetBuffers(workerID int) ([]byte, []byte) {
	return cc.Buffers[workerID], cc.Buffers[workerID]
}

func (cc *CaesarCipher) GetBlockSize() int {
	return cc.BlockSize
}

func (cc *CaesarCipher) GetNumWorkers() int {
	return len(cc.Buffers)
}

func (cc *CaesarCipher) EncryptBlock(dst []byte, src []byte) error {
	if cc.Key == 0 {
		copy(dst, src)
		return nil
	}

	for index, char := range src {
		dst[index] = cc.SubstitutionTable[char]
	}

	return nil
}
func (cc *CaesarCipher) DecryptBlock(dst []byte, src []byte) error {
	if cc.Key == 0 {
		copy(dst, src)
		return nil
	}

	for index, char := range src {
		dst[index] = cc.ReverseTable[char]
	}

	return nil
}
