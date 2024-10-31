// Package encryption provides functionality for file encryption and decryption using AES
// in either CBC or ECB mode. It supports concurrent processing of multiple files with
// configurable parallelism.
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
	// defaultBufferSize defines the size of the buffer used for file I/O operations.
	defaultBufferSize = 32 * 1024 // 32KB default buffer size
)

var (
	// blockPool provides a pool of reusable byte slices for block encryption operations.
	blockPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, aes.BlockSize)
		},
	}

	// bufferPool provides a pool of reusable byte slices for file I/O operations.
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, defaultBufferSize)
		},
	}
)

// CipherMode represents the encryption mode to be used (CBC or ECB).
type CipherMode byte

const (
	// ModeCBC represents Cipher Block Chaining mode.
	ModeCBC CipherMode = iota
	// ModeECB represents Electronic Code Book mode.
	ModeECB
)

// Result represents the outcome of processing a single file.
type Result struct {
	Input  string // Input file path
	Output string // Output file path
	Error  error  // Any error that occurred during processing
}

// Processor handles the encryption and decryption of files.
type Processor struct {
	cfg     config.Config // Configuration for the processor
	cipher  cipher.Block  // AES cipher block
	results chan Result   // Channel for collecting processing results
}

// NewProcessor creates a new Processor with the given configuration.
// It initializes the AES cipher using the provided key.
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

// ProcessFiles concurrently processes all files specified in the configuration.
// It encrypts or decrypts files based on the configuration settings.
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

	err := g.Wait()
	close(p.results)
	<-done // Wait for printer to finish
	return err
}

// encrypt reads data from r, encrypts it using the configured mode,
// and writes the result to w. The isExec parameter preserves the executable bit information.
func (p *Processor) encrypt(r io.Reader, w io.Writer, isExec bool) error {
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

	// Write header with mode and executable bit
	header := []byte{byte(mode)}
	if isExec {
		header = append(header, 1)
	} else {
		header = append(header, 0)
	}

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	if _, err := w.Write(ciphertext); err != nil {
		return fmt.Errorf("writing encrypted data: %w", err)
	}

	return nil
}

// decrypt reads encrypted data from r, decrypts it using the mode specified in the header,
// and writes the result to w. It returns whether the original file was executable.
func (p *Processor) decrypt(r io.Reader, w io.Writer) (bool, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return false, fmt.Errorf("reading header: %w", err)
	}

	mode := CipherMode(header[0])
	isExec := header[1] == 1

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

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

// processFile handles the encryption or decryption of a single file.
// It creates a temporary file for output and performs an atomic rename on completion.
func (p *Processor) processFile(filename, outPath string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("getting file info for %q: %w", filename, err)
	}

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

// encryptECB encrypts data using ECB mode. Note that ECB mode is not
// cryptographically secure and should only be used when deterministic
// encryption is specifically required.
func (p *Processor) encryptECB(data []byte) []byte {
	ciphertext := make([]byte, len(data))
	size := p.cipher.BlockSize()

	buf := blockPool.Get().([]byte)
	defer blockPool.Put(buf)

	for i := 0; i < len(data); i += size {
		p.cipher.Encrypt(ciphertext[i:i+size], data[i:i+size])
	}
	return ciphertext
}

// decryptECB decrypts data that was encrypted using ECB mode.
func (p *Processor) decryptECB(data []byte) []byte {
	plaintext := make([]byte, len(data))
	size := p.cipher.BlockSize()

	buf := blockPool.Get().([]byte)
	defer blockPool.Put(buf)

	for i := 0; i < len(data); i += size {
		p.cipher.Decrypt(plaintext[i:i+size], data[i:i+size])
	}
	return plaintext
}

// outputPath generates the output file path based on the input filename
// and the configured suffixes for encryption/decryption.
func (p *Processor) outputPath(filename string) string {
	ext := p.cfg.EncryptSuffix
	if p.cfg.Decrypt {
		filename = strings.TrimSuffix(filename, p.cfg.EncryptSuffix)
		ext = p.cfg.DecryptSuffix
	}

	return filepath.Join(filepath.Dir(filename),
		filepath.Base(filename)+ext)
}

// pkcs7Pad adds PKCS#7 padding to the data to make it a multiple of blockSize.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS#7 padding from the data.
// It returns an error if the padding is invalid.
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
