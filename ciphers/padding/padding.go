package padding

import (
	"fmt"
)

/*
ISOIEC7816Pad adds ISO/IEC 7816-4:2005 padding to the provided block.

https://en.wikipedia.org/wiki/Padding_(cryptography)#ISO/IEC_7816-4
*/
func ISOIEC7816Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("blockSize must be > 0, got %d", blockSize)
	}

	paddingLen := blockSize - (len(data) % blockSize)

	result := make([]byte, len(data)+paddingLen)
	copy(result, data)
	result[len(data)] = 0x80

	return result, nil
}

/*
ISOIEC7816Unpad removes ISO/IEC 7816-4:2005 padding from the provided block.

https://en.wikipedia.org/wiki/Padding_(cryptography)#ISO/IEC_7816-4
*/
func ISOIEC7816Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("blockSize must be > 0, got %d", blockSize)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("data length %d is not a multiple of blockSize %d", len(data), blockSize)
	}

	for i := len(data) - 1; i >= len(data)-blockSize; i-- {
		if data[i] == 0x80 {
			return data[:i], nil
		}

		if data[i] != 0x00 {
			break
		}
	}

	return nil, fmt.Errorf("invalid padding: no 0x80 marker found in block")
}
