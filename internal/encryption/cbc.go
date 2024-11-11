package encryption

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// jscpd:ignore-start

// encryptCBC encrypts the input file using AES in CBC mode.
func (p *Processor) encryptCBC(r io.Reader, w io.Writer) error {
	// Generate and write IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("generating IV: %w", err)
	}
	if _, err := w.Write(iv); err != nil {
		return fmt.Errorf("writing IV: %w", err)
	}

	cbcMode := cipher.NewCBCEncrypter(p.cipher, iv)
	bufReader := bufio.NewReaderSize(r, defaultBufferSize)

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	blockBuf := make([]byte, 0, 2*aes.BlockSize)
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

			if _, err := w.Write(ciphertext); err != nil {
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

			if _, err := w.Write(ciphertext); err != nil {
				return fmt.Errorf("writing final encrypted block: %w", err)
			}
			break
		}
	}

	return nil
}

// decryptCBC decrypts the input file using AES in CBC mode.
func (p *Processor) decryptCBC(r io.Reader, w io.Writer) error {
	// Read IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(r, iv); err != nil {
		return fmt.Errorf("reading IV: %w", err)
	}

	cbcMode := cipher.NewCBCDecrypter(p.cipher, iv)
	bufReader := bufio.NewReaderSize(r, defaultBufferSize)

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	var lastBlock []byte
	blockBuf := make([]byte, 0, 2*aes.BlockSize)
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

			if _, err := w.Write(plaintext); err != nil {
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

			if _, err := w.Write(unpadded); err != nil {
				return fmt.Errorf("writing final decrypted block: %w", err)
			}
			break
		}
	}

	return nil
}

// jscpd:ignore-end
