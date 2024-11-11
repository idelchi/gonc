package encryption

import (
	"fmt"
)

var (
	// ErrEmptyData is returned when attempting to process empty input data.
	ErrEmptyData = fmt.Errorf("empty data")
	// ErrInvalidPadding is returned when PKCS7 padding is malformed.
	ErrInvalidPadding = fmt.Errorf("invalid padding")
	// ErrInvalidBlockSize is returned when encrypted data length is not aligned with AES block size.
	ErrInvalidBlockSize = fmt.Errorf("ciphertext is not a multiple of block size")
)
