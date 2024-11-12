package encryption

import "errors"

var (
	// ErrEmptyData is returned when attempting to process empty input data.
	ErrEmptyData = errors.New("empty data")
	// ErrInvalidPadding is returned when PKCS7 padding is malformed.
	ErrInvalidPadding = errors.New("invalid padding")
	// ErrInvalidBlockSize is returned when encrypted data length is not aligned with AES block size.
	ErrInvalidBlockSize = errors.New("ciphertext is not a multiple of block size")
)
