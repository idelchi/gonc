// internal/encryption/encryption.go
package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/idelchi/gonc/internal/config"
	"golang.org/x/sync/errgroup"
)

type CipherMode byte

const (
	ModeCBC CipherMode = iota
	ModeECB
)

// Add a small header to identify the encryption mode
func (p *Processor) encrypt(data []byte) ([]byte, error) {
	// Pad data to block size
	padded := pkcs7Pad(data, aes.BlockSize)

	var (
		ciphertext []byte
		mode       CipherMode
	)

	if p.cfg.Deterministic {
		mode = ModeECB
		ciphertext = p.encryptECB(padded)
	} else {
		mode = ModeCBC
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, fmt.Errorf("generating IV: %w", err)
		}

		cbcMode := cipher.NewCBCEncrypter(p.cipher, iv)
		ciphertext = make([]byte, len(padded))
		cbcMode.CryptBlocks(ciphertext, padded)

		// For CBC, prepend IV to ciphertext
		ciphertext = append(iv, ciphertext...)
	}

	// Prepend mode identifier
	return append([]byte{byte(mode)}, ciphertext...), nil
}

func (p *Processor) decrypt(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short")
	}

	// Extract mode
	mode := CipherMode(data[0])
	data = data[1:]

	switch mode {
	case ModeCBC:
		if len(data) < aes.BlockSize {
			return nil, fmt.Errorf("data too short for CBC mode")
		}
		iv := data[:aes.BlockSize]
		ciphertext := data[aes.BlockSize:]

		cbcMode := cipher.NewCBCDecrypter(p.cipher, iv)
		plaintext := make([]byte, len(ciphertext))
		cbcMode.CryptBlocks(plaintext, ciphertext)
		return pkcs7Unpad(plaintext)

	case ModeECB:
		plaintext := p.decryptECB(data)
		return pkcs7Unpad(plaintext)

	default:
		return nil, fmt.Errorf("unknown encryption mode: %d", mode)
	}
}

type Result struct {
	Input  string
	Output string
	Error  error
}

type Processor struct {
	cfg     config.Config
	cipher  cipher.Block
	results chan Result
}

func NewProcessor(cfg config.Config) (*Processor, error) {
	key, err := hex.DecodeString(cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("decoding key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	return &Processor{
		cfg:     cfg,
		cipher:  block,
		results: make(chan Result, len(cfg.Files)),
	}, nil
}

func (p *Processor) ProcessFiles() error {
	g := new(errgroup.Group)
	g.SetLimit(p.cfg.Parallel)

	// Start result printer
	done := make(chan struct{})
	go func() {
		defer close(done)
		for result := range p.results {
			if result.Error != nil {
				fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", result.Input, result.Error)
			} else {
				fmt.Printf("Processed %s -> %s\n", result.Input, result.Output)
			}
		}
	}()

	// Process files
	for _, file := range p.cfg.Files {
		file := file // Capture for closure
		g.Go(func() error {
			outPath := p.outputPath(file)
			if err := p.processFile(file, outPath); err != nil {
				p.results <- Result{Input: file, Error: err}
				return err
			}
			p.results <- Result{Input: file, Output: outPath}
			return nil
		})
	}

	// Wait for all processing to complete
	err := g.Wait()
	close(p.results)
	<-done // Wait for printer to finish
	return err
}

func (p *Processor) processFile(filename, outPath string) error {
	input, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	var output []byte
	if p.cfg.Decrypt {
		output, err = p.decrypt(input)
	} else {
		output, err = p.encrypt(input)
	}
	if err != nil {
		return err
	}

	return os.WriteFile(outPath, output, 0o600)
}

func (p *Processor) encryptECB(data []byte) []byte {
	ciphertext := make([]byte, len(data))
	size := p.cipher.BlockSize()

	for i := 0; i < len(data); i += size {
		p.cipher.Encrypt(ciphertext[i:i+size], data[i:i+size])
	}
	return ciphertext
}

func (p *Processor) decryptECB(data []byte) []byte {
	plaintext := make([]byte, len(data))
	size := p.cipher.BlockSize()

	for i := 0; i < len(data); i += size {
		p.cipher.Decrypt(plaintext[i:i+size], data[i:i+size])
	}
	return plaintext
}

func (p *Processor) outputPath(filename string) string {
	ext := ".enc"
	if p.cfg.Decrypt {
		ext = ".dec"
	}
	return filepath.Join(filepath.Dir(filename),
		filepath.Base(filename)+ext)
}

// PKCS7 padding implementation
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("empty data")
	}

	padding := int(data[length-1])
	if padding > length || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}

	// Verify padding
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:length-padding], nil
}
