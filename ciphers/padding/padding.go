package padding

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func Pad(data []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(data) % blockSize)
	pad := bytes.Repeat([]byte{byte(0x20)}, paddingLen-4)

	padBlock := make([]byte, 4)
	binary.BigEndian.PutUint32(padBlock, uint32(paddingLen))

	data = append(data, pad...)
	return append(data, padBlock...)
}

func Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data")
	}

	paddingLen := binary.BigEndian.Uint32(data[len(data)-4:])
	if paddingLen == 0 || paddingLen > uint32(blockSize) {
		return nil, fmt.Errorf("invalid padded data")
	}

	return data[:len(data)-int(paddingLen)], nil
}
