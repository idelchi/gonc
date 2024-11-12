package encryption

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// jscpd:ignore-start

// encryptCBC encrypts the input file using AES in CBC mode.
//
//nolint:funlen,cyclop
func (p *Processor) encryptCBC(reader io.Reader, writer io.Writer) error {
	// Generate and write IV
	initializationVector := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, initializationVector); err != nil {
		return fmt.Errorf("generating IV: %w", err)
	}

	if _, err := writer.Write(initializationVector); err != nil {
		return fmt.Errorf("writing IV: %w", err)
	}

	cbcMode := cipher.NewCBCEncrypter(p.cipher, initializationVector)
	bufReader := bufio.NewReaderSize(reader, defaultBufferSize)

	buf, ok := bufferPool.Get().([]byte)
	if !ok {
		return errors.New("invalid buffer type from pool") //nolint:err113
	}

	defer bufferPool.Put(buf) //nolint:staticcheck

	const twoBlocks = 2 * aes.BlockSize

	blockBuf := make([]byte, 0, twoBlocks)
	isEOF := false

	// Process the file in chunks
	for !isEOF {
		// Read more data if needed
		n, err := bufReader.Read(buf)
		if n > 0 {
			blockBuf = append(blockBuf, buf[:n]...)
		}

		if err == io.EOF {
			isEOF = true
		} else if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}

		// Process complete blocks, keeping last block for padding if needed
		for len(blockBuf) >= aes.BlockSize {
			// If this is the last data and last block, break to handle padding
			if isEOF && len(blockBuf) == aes.BlockSize {
				break
			}

			ciphertext := make([]byte, aes.BlockSize)
			cbcMode.CryptBlocks(ciphertext, blockBuf[:aes.BlockSize])

			if _, err := writer.Write(ciphertext); err != nil {
				return fmt.Errorf("writing encrypted block: %w", err)
			}

			blockBuf = blockBuf[aes.BlockSize:]
		}

		// Handle final block with padding if we've reached EOF
		if isEOF {
			// Apply padding
			padded := pkcs7Pad(blockBuf, aes.BlockSize)
			ciphertext := make([]byte, len(padded))
			cbcMode.CryptBlocks(ciphertext, padded)

			if _, err := writer.Write(ciphertext); err != nil {
				return fmt.Errorf("writing final encrypted block: %w", err)
			}

			break
		}
	}

	return nil
}

// decryptCBC decrypts the input file using AES in CBC mode.
//
//nolint:funlen,cyclop
func (p *Processor) decryptCBC(reader io.Reader, writer io.Writer) error {
	// Read IV
	initializationVector := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(reader, initializationVector); err != nil {
		return fmt.Errorf("reading IV: %w", err)
	}

	cbcMode := cipher.NewCBCDecrypter(p.cipher, initializationVector)
	bufReader := bufio.NewReaderSize(reader, defaultBufferSize)

	buf, ok := bufferPool.Get().([]byte)
	if !ok {
		return errors.New("invalid buffer type from pool") //nolint:err113
	}

	defer bufferPool.Put(buf) //nolint:staticcheck

	var lastBlock []byte

	const twoBlocks = 2 * aes.BlockSize

	blockBuf := make([]byte, 0, twoBlocks)
	isEOF := false

	// Process the file in chunks
	for !isEOF {
		// Read more data if needed
		n, err := bufReader.Read(buf)
		if n > 0 {
			blockBuf = append(blockBuf, buf[:n]...)
		}

		if err == io.EOF {
			isEOF = true
		} else if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}

		// Ensure we have complete blocks
		if len(blockBuf)%aes.BlockSize != 0 && isEOF {
			return ErrInvalidBlockSize
		}

		// Process complete blocks except the last block
		for len(blockBuf) >= 2*aes.BlockSize {
			plaintext := make([]byte, aes.BlockSize)
			cbcMode.CryptBlocks(plaintext, blockBuf[:aes.BlockSize])

			if _, err := writer.Write(plaintext); err != nil {
				return fmt.Errorf("writing decrypted block: %w", err)
			}

			blockBuf = blockBuf[aes.BlockSize:]
		}

		// If this is the last block and we have a complete block, process it
		if isEOF && len(blockBuf) == aes.BlockSize {
			lastBlock = make([]byte, aes.BlockSize)
			cbcMode.CryptBlocks(lastBlock, blockBuf)

			// Remove padding from the last block
			unpadded, err := pkcs7Unpad(lastBlock)
			if err != nil {
				return fmt.Errorf("removing padding: %w", err)
			}

			if _, err := writer.Write(unpadded); err != nil {
				return fmt.Errorf("writing final decrypted block: %w", err)
			}

			break
		}
	}

	return nil
}

// jscpd:ignore-end
