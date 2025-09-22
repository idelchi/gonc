package encryption

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/tink"
)

// streamingWriter wraps an io.Writer with deterministic encryption capabilities.
type streamingWriter struct {
	w          io.Writer
	daead      tink.DeterministicAEAD
	buffer     []byte
	header     []byte
	chunkIndex uint64
}

// newStreamingWriter creates a writer that encrypts data in chunks using the provided DAEAD.
func newStreamingWriter(w io.Writer, daead tink.DeterministicAEAD, header []byte) *streamingWriter {
	hdrCopy := make([]byte, len(header))
	copy(hdrCopy, header)

	return &streamingWriter{
		w:          w,
		daead:      daead,
		buffer:     make([]byte, 0, chunkSize),
		header:     hdrCopy,
		chunkIndex: 0,
	}
}

// Write implements io.Writer, buffering data until a complete chunk can be encrypted.
func (sw *streamingWriter) Write(data []byte) (int, error) {
	sw.buffer = append(sw.buffer, data...)

	for len(sw.buffer) >= chunkSize {
		if err := sw.flushChunk(chunkSize); err != nil {
			return 0, err
		}
	}

	return len(data), nil
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
	if size > chunkSize {
		return errors.New("chunk size exceeds maximum allowed size")
	}

	chunk := make([]byte, size)
	copy(chunk, sw.buffer[:size])

	ad := buildChunkAssociatedData(sw.header, sw.chunkIndex)

	encrypted, err := sw.daead.EncryptDeterministically(chunk, ad)
	if err != nil {
		return fmt.Errorf("encrypting chunk: %w", err)
	}

	// Write ciphertext length followed by ciphertext
	if err := binary.Write(sw.w, binary.BigEndian, uint32(len(encrypted))); err != nil { //nolint:gosec
		return fmt.Errorf("writing chunk size: %w", err)
	}

	if _, err := sw.w.Write(encrypted); err != nil {
		return fmt.Errorf("writing encrypted chunk: %w", err)
	}

	sw.buffer = sw.buffer[size:]
	sw.chunkIndex++

	return nil
}

func buildChunkAssociatedData(header []byte, index uint64) []byte {
	const chunkIndexSize = 8

	ad := make([]byte, len(header)+chunkIndexSize)
	copy(ad, header)
	binary.BigEndian.PutUint64(ad[len(header):], index)

	return ad
}
