package ciphers

type RailFenceCipher struct {
	Key int
}

func NewRailFenceCipher(key int) *RailFenceCipher {
	return &RailFenceCipher{
		Key: key,
	}
}

func (rfCipher *RailFenceCipher) EncryptBlock(block []byte, buffer []byte) error {
	if rfCipher.Key <= 1 {
		return nil
	}

	cycle := 2 * (rfCipher.Key - 1)
	blockSize := len(block)

	index := 0
	for rail := rfCipher.Key - 1; rail >= 0; rail-- {
		for blockIndex := rail; blockIndex < blockSize; blockIndex += cycle {
			buffer[index] = block[blockIndex]
			index += 1

			// if middle rail
			secondBlockIndex := blockIndex + cycle - 2*rail
			if rail != 0 && rail != rfCipher.Key-1 && secondBlockIndex < blockSize {
				buffer[index] = block[secondBlockIndex]
				index += 1
			}
		}
	}

	copy(block, buffer)
	return nil
}

func (rfCipher *RailFenceCipher) DecryptBlock(block []byte, buffer []byte) error {
	if rfCipher.Key <= 1 || len(block) == 0 {
		return nil
	}

	cycle := 2 * (rfCipher.Key - 1)
	blockSize := len(block)

	// Count offset of each row
	// TODO: Fix this bullshit
	railOffset := make([]int, rfCipher.Key)
	currentOffset := 0
	for rail := rfCipher.Key - 1; rail >= 0; rail-- {
		railOffset[rail] = currentOffset

		for blockIndex := rail; blockIndex < blockSize; blockIndex += cycle {
			currentOffset += 1

			if rail != 0 && rail != rfCipher.Key-1 {
				if secondBlockIndex := blockIndex + cycle - 2*rail; secondBlockIndex < blockSize {
					currentOffset += 1
				}
			}
		}
	}

	currentRail := 0
	direction := 1

	for index := range blockSize {
		buffer[index] = block[railOffset[currentRail]]
		railOffset[currentRail] += 1

		switch currentRail {
		case 0:
			direction = 1
		case rfCipher.Key - 1:
			direction = -1
		}

		currentRail += direction
	}

	copy(block, buffer)
	return nil
}
