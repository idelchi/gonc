package encryption

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/tink"
)

// streamingWriter wraps an io.Writer with deterministic encryption capabilities
type streamingWriter struct {
	w              io.Writer
	daead          tink.DeterministicAEAD
	buffer         []byte
	associatedData []byte
}

func newStreamingWriter(w io.Writer, daead tink.DeterministicAEAD, associatedData []byte) *streamingWriter {
	return &streamingWriter{
		w:              w,
		daead:          daead,
		buffer:         make([]byte, 0, chunkSize),
		associatedData: associatedData,
	}
}

func (sw *streamingWriter) Write(p []byte) (int, error) {
	sw.buffer = append(sw.buffer, p...)

	// Process complete chunks
	for len(sw.buffer) >= chunkSize {
		if err := sw.flushChunk(chunkSize); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

func (sw *streamingWriter) Close() error {
	// Flush any remaining data
	if len(sw.buffer) > 0 {
		return sw.flushChunk(len(sw.buffer))
	}
	return nil
}

func (sw *streamingWriter) flushChunk(size int) error {
	chunk := sw.buffer[:size]
	encrypted, err := sw.daead.EncryptDeterministically(chunk, sw.associatedData)
	if err != nil {
		return fmt.Errorf("encrypting chunk: %w", err)
	}

	// Write chunk size and encrypted data
	if err := binary.Write(sw.w, binary.BigEndian, uint32(len(encrypted))); err != nil {
		return fmt.Errorf("writing chunk size: %w", err)
	}
	if _, err := sw.w.Write(encrypted); err != nil {
		return fmt.Errorf("writing encrypted chunk: %w", err)
	}

	sw.buffer = sw.buffer[size:]
	return nil
}
