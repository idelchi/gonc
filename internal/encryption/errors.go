package encryption

import (
	"fmt"
)

var (
	ErrEmptyData        = fmt.Errorf("empty data")
	ErrInvalidPadding   = fmt.Errorf("invalid padding")
	ErrInvalidBlockSize = fmt.Errorf("ciphertext is not a multiple of block size")
)
