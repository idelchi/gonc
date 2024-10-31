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
	"strings"
	"sync"

	"github.com/idelchi/gonc/internal/config"
	"golang.org/x/sync/errgroup"
)

const (
	defaultBufferSize = 32 * 1024 // 32KB default buffer size
)

var (
	blockPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, aes.BlockSize)
		},
	}

	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, defaultBufferSize)
		},
	}
)

type CipherMode byte

const (
	ModeCBC CipherMode = iota
	ModeECB
)

// Add a small header to identify the encryption mode and executable bit
func (p *Processor) encrypt(r io.Reader, w io.Writer, isExec bool) error {
	// Get buffer from pool for reading
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	// Read all data into a buffer (required for padding)
	var data []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}
	}

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
			return fmt.Errorf("generating IV: %w", err)
		}

		cbcMode := cipher.NewCBCEncrypter(p.cipher, iv)
		ciphertext = make([]byte, len(padded))
		cbcMode.CryptBlocks(ciphertext, padded)

		// For CBC, prepend IV to ciphertext
		ciphertext = append(iv, ciphertext...)
	}

	// Prepend mode identifier and executable bit
	header := []byte{byte(mode)}
	if isExec {
		header = append(header, 1)
	} else {
		header = append(header, 0)
	}

	// Write header
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	// Write encrypted data
	if _, err := w.Write(ciphertext); err != nil {
		return fmt.Errorf("writing encrypted data: %w", err)
	}

	return nil
}

func (p *Processor) decrypt(r io.Reader, w io.Writer) (bool, error) {
	// Read header
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return false, fmt.Errorf("reading header: %w", err)
	}

	mode := CipherMode(header[0])
	isExec := header[1] == 1

	// Get buffer from pool
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	// Read all encrypted data
	var data []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("reading encrypted data: %w", err)
		}
	}

	switch mode {
	case ModeCBC:
		if len(data) < aes.BlockSize {
			return false, fmt.Errorf("data too short for CBC mode")
		}
		iv := data[:aes.BlockSize]
		ciphertext := data[aes.BlockSize:]

		cbcMode := cipher.NewCBCDecrypter(p.cipher, iv)
		plaintext := make([]byte, len(ciphertext))
		cbcMode.CryptBlocks(plaintext, ciphertext)
		unpadded, err := pkcs7Unpad(plaintext)
		if err != nil {
			return false, err
		}
		_, err = w.Write(unpadded)
		return isExec, err

	case ModeECB:
		plaintext := p.decryptECB(data)
		unpadded, err := pkcs7Unpad(plaintext)
		if err != nil {
			return false, err
		}
		_, err = w.Write(unpadded)
		return isExec, err

	default:
		return false, fmt.Errorf("unknown encryption mode: %d", mode)
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
	info, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("getting file info for %q: %w", filename, err)
	}

	// Check if file is executable (any execute bit is set)
	isExec := info.Mode()&0o111 != 0

	// Create temporary output file
	tmpFile, err := os.CreateTemp(filepath.Dir(outPath), ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		if err != nil {
			os.Remove(tmpName)
		}
	}()

	// Open input file
	inFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("opening input file: %w", err)
	}
	defer inFile.Close()

	if p.cfg.Decrypt {
		execOut, err := p.decrypt(inFile, tmpFile)
		if err != nil {
			return err
		}
		// Set output permissions based on executable bit
		perm := os.FileMode(0o600)
		if execOut {
			perm |= 0o111
		}
		if err := os.Chmod(tmpName, perm); err != nil {
			return fmt.Errorf("setting file permissions: %w", err)
		}
	} else {
		if err := p.encrypt(inFile, tmpFile, isExec); err != nil {
			return err
		}
	}

	// Close files before rename
	tmpFile.Close()
	inFile.Close()

	// Atomic rename
	if err := os.Rename(tmpName, outPath); err != nil {
		return fmt.Errorf("renaming output file: %w", err)
	}

	return nil
}

func (p *Processor) encryptECB(data []byte) []byte {
	ciphertext := make([]byte, len(data))
	size := p.cipher.BlockSize()

	// Get buffer from pool
	buf := blockPool.Get().([]byte)
	defer blockPool.Put(buf)

	for i := 0; i < len(data); i += size {
		p.cipher.Encrypt(ciphertext[i:i+size], data[i:i+size])
	}
	return ciphertext
}

func (p *Processor) decryptECB(data []byte) []byte {
	plaintext := make([]byte, len(data))
	size := p.cipher.BlockSize()

	// Get buffer from pool
	buf := blockPool.Get().([]byte)
	defer blockPool.Put(buf)

	for i := 0; i < len(data); i += size {
		p.cipher.Decrypt(plaintext[i:i+size], data[i:i+size])
	}
	return plaintext
}

func (p *Processor) outputPath(filename string) string {
	ext := p.cfg.EncryptSuffix
	if p.cfg.Decrypt {
		// Strip suffix
		filename = strings.TrimSuffix(filename, p.cfg.EncryptSuffix)
		ext = p.cfg.DecryptSuffix
	}

	return filepath.Join(filepath.Dir(filename),
		filepath.Base(filename)+ext)
}

// PKCS7 padding implementation with improved error messages
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
		return nil, fmt.Errorf("invalid padding size: %d", padding)
	}

	// Verify padding
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding pattern at position %d", i)
		}
	}

	return data[:length-padding], nil
}
