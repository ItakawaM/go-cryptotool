package ciphers

type RailFenceCipher struct {
	Key              int
	BlockSize        int
	Buffers          [][]byte
	PermutationTable []int
	InverseTable     []int
}

func NewRailFenceCipher(key int, blockSize int, numCPU int) *RailFenceCipher {
	buffers := make([][]byte, numCPU*2)
	for i := range buffers {
		buffers[i] = make([]byte, blockSize)
	}
	permutationTable := make([]int, blockSize)
	inverseTable := make([]int, blockSize)

	return &RailFenceCipher{
		Key:              key,
		BlockSize:        blockSize,
		Buffers:          buffers,
		PermutationTable: permutationTable,
		InverseTable:     inverseTable,
	}
}

func (rfCipher *RailFenceCipher) GetBuffers(workerID int) ([]byte, []byte) {
	return rfCipher.Buffers[workerID*2], rfCipher.Buffers[workerID*2+1]
}

func (rfCipher *RailFenceCipher) GetBlockSize() int {
	return rfCipher.BlockSize
}

func (rfCipher *RailFenceCipher) GetNumWorkers() int {
	return len(rfCipher.Buffers) / 2
}

func (rfCipher *RailFenceCipher) BuildPermutationTable() {
	if rfCipher.Key <= 1 {
		return
		// Reverse order when Key >= BlockSize
	} else if rfCipher.Key >= rfCipher.BlockSize {
		// Blocks are always even numbers
		for index := 0; index < rfCipher.BlockSize/2; index++ {
			rfCipher.PermutationTable[index] = rfCipher.BlockSize - 1 - index
			rfCipher.InverseTable[rfCipher.BlockSize-1-index] = index
		}

		return
	}

	cycle := 2 * (rfCipher.Key - 1)

	rails := make([]int, rfCipher.BlockSize)
	for index := 0; index < rfCipher.BlockSize; index++ {
		cyclePosition := index % cycle
		if cyclePosition < rfCipher.Key {
			rails[index] = cyclePosition
		} else {
			rails[index] = cycle - cyclePosition
		}
	}

	railOffset := make([]int, rfCipher.Key)
	currentOffset := 0
	for rail := rfCipher.Key - 1; rail >= 0; rail-- {
		railOffset[rail] = currentOffset

		for index := rail; index < rfCipher.BlockSize; index += cycle {
			currentOffset += 1

			if rail != 0 && rail != rfCipher.Key-1 {
				if secondIndex := index + cycle - 2*rail; secondIndex < rfCipher.BlockSize {
					currentOffset += 1
				}
			}
		}
	}

	for index := 0; index < rfCipher.BlockSize; index++ {
		rfCipher.PermutationTable[index] = railOffset[rails[index]]
		rfCipher.InverseTable[railOffset[rails[index]]] = index
		railOffset[rails[index]]++
	}
}

func (rfCipher *RailFenceCipher) EncryptBlock(dst []byte, src []byte) error {
	if rfCipher.Key <= 1 {
		return nil
	}

	for index := 0; index < rfCipher.BlockSize; index++ {
		dst[rfCipher.PermutationTable[index]] = src[index]
	}

	return nil
}

func (rfCipher *RailFenceCipher) DecryptBlock(dst []byte, src []byte) error {
	if rfCipher.Key <= 1 {
		return nil
	}

	for index := 0; index < rfCipher.BlockSize; index++ {
		dst[rfCipher.InverseTable[index]] = src[index]
	}

	return nil
}
