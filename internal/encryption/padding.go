package encryption

import (
	"bytes"
	"crypto/aes"
	"fmt"
)

// pkcs7Pad adds PKCS#7 padding to the data to make it a multiple of blockSize.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS#7 padding from the data.
// It returns an error if the padding is invalid.
func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, ErrEmptyData
	}

	padding := int(data[length-1])
	if padding > length || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding size: %d", padding)
	}

	// Verify padding
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, ErrInvalidPadding
		}
	}

	return data[:length-padding], nil
}
