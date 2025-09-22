package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

const randomizedBufferSize = 4096

func (p *Processor) encryptRandomized(reader io.Reader, writer io.Writer, header []byte) error {
	if len(p.key) != AesKeySize {
		return fmt.Errorf("encrypt: randomized mode requires %d-byte key", AesKeySize)
	}

	encKey, macKey, err := deriveRandomizedKeys(p.key)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	mac := hmac.New(sha256.New, macKey)
	mac.Write(header)

	initializationVector := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, initializationVector); err != nil {
		return fmt.Errorf("generating IV: %w", err)
	}

	if _, err := writer.Write(initializationVector); err != nil {
		return fmt.Errorf("writing IV: %w", err)
	}

	mac.Write(initializationVector)

	stream := cipher.NewCTR(block, initializationVector)
	buf := make([]byte, randomizedBufferSize)
	encrypted := make([]byte, randomizedBufferSize)

	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			stream.XORKeyStream(encrypted[:n], buf[:n])
			mac.Write(encrypted[:n])

			if _, err := writer.Write(encrypted[:n]); err != nil {
				return fmt.Errorf("writing ciphertext: %w", err)
			}
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			return fmt.Errorf("reading plaintext: %w", readErr)
		}
	}

	tag := mac.Sum(nil)
	if _, err := writer.Write(tag); err != nil {
		return fmt.Errorf("writing authentication tag: %w", err)
	}

	return nil
}

//nolint:gocognit
func (p *Processor) decryptRandomized(reader io.Reader, writer io.Writer, header []byte) error {
	if len(p.key) != AesKeySize {
		return fmt.Errorf("decrypt: randomized mode requires %d-byte key", AesKeySize)
	}

	encKey, macKey, err := deriveRandomizedKeys(p.key)
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, macKey)
	mac.Write(header)

	initializationVector := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(reader, initializationVector); err != nil {
		return fmt.Errorf("reading IV: %w", err)
	}

	mac.Write(initializationVector)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	stream := cipher.NewCTR(block, initializationVector)
	buf := make([]byte, randomizedBufferSize)
	plain := make([]byte, randomizedBufferSize)
	tagBuffer := make([]byte, 0, envelopeTagSize)

	for {
		n, readErr := reader.Read(buf)
		if n > 0 { //nolint:nestif
			combined := append(tagBuffer, buf[:n]...) //nolint:gocritic

			if len(combined) <= envelopeTagSize {
				tagBuffer = combined
			} else {
				processLen := len(combined) - envelopeTagSize
				chunk := combined[:processLen]

				tagBuffer = append(tagBuffer[:0], combined[processLen:]...)

				mac.Write(chunk)

				if len(plain) < processLen {
					plain = make([]byte, processLen)
				}

				stream.XORKeyStream(plain[:processLen], chunk)

				if _, err := writer.Write(plain[:processLen]); err != nil {
					return fmt.Errorf("writing plaintext: %w", err)
				}
			}
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			return fmt.Errorf("reading ciphertext: %w", readErr)
		}
	}

	if len(tagBuffer) != envelopeTagSize {
		return fmt.Errorf("%w: authentication tag missing", ErrProcessing)
	}

	if !hmac.Equal(mac.Sum(nil), tagBuffer) {
		return fmt.Errorf("%w: authentication failed", ErrProcessing)
	}

	return nil
}
