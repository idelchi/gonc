package encryption

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/tink"
)

// streamingWriter wraps an io.Writer with deterministic encryption capabilities.
type streamingWriter struct {
	// w is the underlying writer for encrypted data
	w io.Writer

	// daead handles deterministic authenticated encryption
	daead tink.DeterministicAEAD

	// buffer accumulates data until it reaches chunk size
	buffer []byte

	// associatedData is authenticated but not encrypted
	associatedData []byte
}

// newStreamingWriter creates a writer that encrypts data in chunks using the provided DAEAD.
func newStreamingWriter(w io.Writer, daead tink.DeterministicAEAD, associatedData []byte) *streamingWriter {
	return &streamingWriter{
		w:              w,
		daead:          daead,
		buffer:         make([]byte, 0, chunkSize),
		associatedData: associatedData,
	}
}

// Write implements io.Writer, buffering data until a complete chunk can be encrypted.
func (sw *streamingWriter) Write(p []byte) (int, error) {
	sw.buffer = append(sw.buffer, p...)

	for len(sw.buffer) >= chunkSize {
		if err := sw.flushChunk(chunkSize); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

// Close implements io.Closer, encrypting any remaining buffered data.
func (sw *streamingWriter) Close() error {
	if len(sw.buffer) > 0 {
		return sw.flushChunk(len(sw.buffer))
	}
	return nil
}

// flushChunk encrypts and writes a chunk of the specified size.
func (sw *streamingWriter) flushChunk(size int) error {
	chunk := sw.buffer[:size]
	encrypted, err := sw.daead.EncryptDeterministically(chunk, sw.associatedData)
	if err != nil {
		return fmt.Errorf("encrypting chunk: %w", err)
	}

	if err := binary.Write(sw.w, binary.BigEndian, uint32(len(encrypted))); err != nil {
		return fmt.Errorf("writing chunk size: %w", err)
	}

	if _, err := sw.w.Write(encrypted); err != nil {
		return fmt.Errorf("writing encrypted chunk: %w", err)
	}

	sw.buffer = sw.buffer[size:]
	return nil
}
