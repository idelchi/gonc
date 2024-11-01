package encryption

import (
	"sync"
)

const defaultBufferSize = 32 * 1024 // 32KB default buffer size

// bufferPool provides a pool of reusable byte slices for file I/O operations.
var bufferPool = sync.Pool{
	New: func() any {
		return make([]byte, defaultBufferSize)
	},
}
