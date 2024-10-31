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
	"runtime"
	"strings"
	"sync"

	"github.com/idelchi/gonc/internal/config"
	"golang.org/x/sync/errgroup"
)

const (
	// Chunk size for parallel processing (must be multiple of BlockSize)
	chunkSize = 1 * 1024 * 1024 // 1MB
	// Maximum number of segments to process in parallel per file
	maxSegments = 8
)

type CipherMode byte

const (
	ModeCBC CipherMode = iota
	ModeECB
)

// Buffer pools for common operations
var (
	chunkPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, chunkSize)
		},
	}

	blockPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, aes.BlockSize)
		},
	}
)

type Result struct {
	Input  string
	Output string
	Error  error
}

type Processor struct {
	cfg     config.Config
	cipher  cipher.Block
	results chan Result
	workers int
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

	// Optimize number of workers based on CPU cores and parallel setting
	workers := runtime.NumCPU()
	if cfg.Parallel > 0 && cfg.Parallel < workers {
		workers = cfg.Parallel
	}

	return &Processor{
		cfg:     cfg,
		cipher:  block,
		results: make(chan Result, workers*2), // Buffer channel based on worker count
		workers: workers,
	}, nil
}

func (p *Processor) ProcessFiles() error {
	g := new(errgroup.Group)
	g.SetLimit(p.workers)

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
		file := file
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
	<-done
	return err
}

func (p *Processor) processFile(inPath, outPath string) error {
	info, err := os.Stat(inPath)
	if err != nil {
		return fmt.Errorf("getting file info: %w", err)
	}

	isExec := info.Mode()&0o111 != 0

	// Open files for streaming
	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("opening input file: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening output file: %w", err)
	}
	defer outFile.Close()

	if p.cfg.Decrypt {
		err = p.decryptStream(inFile, outFile, info.Size())
	} else {
		err = p.encryptStream(inFile, outFile, info.Size(), isExec)
	}

	if err != nil {
		return err
	}

	// Set executable bits if needed
	if p.cfg.Decrypt && isExec {
		return os.Chmod(outPath, 0o755)
	}
	return nil
}

func (p *Processor) encryptStream(r io.Reader, w io.Writer, size int64, isExec bool) error {
	// Write header
	mode := ModeCBC
	if p.cfg.Deterministic {
		mode = ModeECB
	}
	header := []byte{byte(mode), 0}
	if isExec {
		header[1] = 1
	}
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	// Initialize encryption parameters
	var iv []byte
	if !p.cfg.Deterministic {
		iv = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return fmt.Errorf("generating IV: %w", err)
		}
		if _, err := w.Write(iv); err != nil {
			return fmt.Errorf("writing IV: %w", err)
		}
	}

	// Calculate optimal number of parallel segments
	numSegments := int(size / chunkSize)
	if numSegments > maxSegments {
		numSegments = maxSegments
	}
	if numSegments < 1 {
		numSegments = 1
	}

	// Process file in parallel segments
	var wg sync.WaitGroup
	errChan := make(chan error, numSegments)
	results := make([][]byte, numSegments)

	for i := 0; i < numSegments; i++ {
		wg.Add(1)
		go func(segment int) {
			defer wg.Done()

			// Get buffer from pool
			buf := chunkPool.Get().([]byte)
			defer chunkPool.Put(buf)

			n, err := r.Read(buf)
			if err != nil && err != io.EOF {
				errChan <- err
				return
			}

			if n > 0 {
				var segmentIV []byte
				if !p.cfg.Deterministic {
					segmentIV = make([]byte, aes.BlockSize)
					copy(segmentIV, iv)
					for j := 0; j < segment; j++ {
						for k := len(segmentIV) - 1; k >= 0; k-- {
							segmentIV[k]++
							if segmentIV[k] != 0 {
								break
							}
						}
					}
				}

				encrypted, err := p.encryptChunk(buf[:n], segmentIV)
				if err != nil {
					errChan <- err
					return
				}
				results[segment] = encrypted
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	if err := <-errChan; err != nil {
		return fmt.Errorf("parallel encryption error: %w", err)
	}

	// Write results in order
	for _, result := range results {
		if result != nil {
			if _, err := w.Write(result); err != nil {
				return fmt.Errorf("writing encrypted data: %w", err)
			}
		}
	}

	return nil
}

func (p *Processor) decryptStream(r io.Reader, w io.Writer, size int64) error {
	// Read header
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("reading header: %w", err)
	}

	mode := CipherMode(header[0])
	isExec := header[1] == 1

	var iv []byte
	if mode == ModeCBC {
		iv = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(r, iv); err != nil {
			return fmt.Errorf("reading IV: %w", err)
		}
	}

	// Calculate segments for parallel processing
	dataSize := size - 2 // Subtract header size
	if mode == ModeCBC {
		dataSize -= aes.BlockSize // Subtract IV size
	}

	numSegments := int(dataSize / chunkSize)
	if numSegments > maxSegments {
		numSegments = maxSegments
	}
	if numSegments < 1 {
		numSegments = 1
	}

	// Process file in parallel segments
	var wg sync.WaitGroup
	errChan := make(chan error, numSegments)
	results := make([][]byte, numSegments)

	for i := 0; i < numSegments; i++ {
		wg.Add(1)
		go func(segment int) {
			defer wg.Done()

			// Get buffer from pool
			buf := chunkPool.Get().([]byte)
			defer chunkPool.Put(buf)

			n, err := r.Read(buf)
			if err != nil && err != io.EOF {
				errChan <- err
				return
			}

			if n > 0 {
				var segmentIV []byte
				if mode == ModeCBC {
					segmentIV = make([]byte, aes.BlockSize)
					copy(segmentIV, iv)
					for j := 0; j < segment; j++ {
						for k := len(segmentIV) - 1; k >= 0; k-- {
							segmentIV[k]++
							if segmentIV[k] != 0 {
								break
							}
						}
					}
				}

				decrypted, err := p.decryptChunk(buf[:n], segmentIV, mode)
				if err != nil {
					errChan <- err
					return
				}
				results[segment] = decrypted
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	if err := <-errChan; err != nil {
		return fmt.Errorf("parallel decryption error: %w", err)
	}

	// Write results in order
	for _, result := range results {
		if result != nil {
			if _, err := w.Write(result); err != nil {
				return fmt.Errorf("writing decrypted data: %w", err)
			}
		}
	}

	// Set file permissions based on executable bit
	if isExec {
		if err := os.Chmod(w.(*os.File).Name(), 0o755); err != nil {
			return fmt.Errorf("setting executable permission: %w", err)
		}
	}

	return nil
}

func (p *Processor) encryptChunk(data []byte, iv []byte) ([]byte, error) {
	// Pad data
	padded := pkcs7Pad(data, aes.BlockSize)

	if p.cfg.Deterministic {
		return p.encryptECB(padded), nil
	}

	// CBC mode
	ciphertext := make([]byte, len(padded))
	cbcMode := cipher.NewCBCEncrypter(p.cipher, iv)
	cbcMode.CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

func (p *Processor) decryptChunk(data []byte, iv []byte, mode CipherMode) ([]byte, error) {
	var plaintext []byte

	if mode == ModeECB {
		plaintext = p.decryptECB(data)
	} else {
		plaintext = make([]byte, len(data))
		cbcMode := cipher.NewCBCDecrypter(p.cipher, iv)
		cbcMode.CryptBlocks(plaintext, data)
	}

	return pkcs7Unpad(plaintext)
}

// Optimized ECB implementation using buffer pooling
func (p *Processor) encryptECB(data []byte) []byte {
	ciphertext := make([]byte, len(data))
	size := p.cipher.BlockSize()

	// Use worker pool for parallel block processing
	numWorkers := runtime.NumCPU()
	var wg sync.WaitGroup
	blockChan := make(chan int, len(data)/size)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := blockPool.Get().([]byte)
			defer blockPool.Put(buffer)

			for blockStart := range blockChan {
				p.cipher.Encrypt(
					ciphertext[blockStart:blockStart+size],
					data[blockStart:blockStart+size],
				)
			}
		}()
	}

	// Feed blocks to workers
	for i := 0; i < len(data); i += size {
		blockChan <- i
	}
	close(blockChan)
	wg.Wait()

	return ciphertext
}

func (p *Processor) decryptECB(data []byte) []byte {
	plaintext := make([]byte, len(data))
	size := p.cipher.BlockSize()

	// Use worker pool for parallel block processing
	numWorkers := runtime.NumCPU()
	var wg sync.WaitGroup
	blockChan := make(chan int, len(data)/size)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := blockPool.Get().([]byte)
			defer blockPool.Put(buffer)

			for blockStart := range blockChan {
				p.cipher.Decrypt(
					plaintext[blockStart:blockStart+size],
					data[blockStart:blockStart+size],
				)
			}
		}()
	}

	// Feed blocks to workers
	for i := 0; i < len(data); i += size {
		blockChan <- i
	}
	close(blockChan)
	wg.Wait()

	return plaintext
}

func (p *Processor) outputPath(filename string) string {
	ext := p.cfg.EncryptSuffix
	if p.cfg.Decrypt {
		filename = strings.TrimSuffix(filename, p.cfg.EncryptSuffix)
		ext = p.cfg.DecryptSuffix
	}
	return filepath.Join(filepath.Dir(filename), filepath.Base(filename)+ext)
}

// Optimized PKCS7 padding implementation using buffer pooling
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
	paddingStart := length - padding
	for i := paddingStart; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding pattern")
		}
	}

	return data[:length-padding], nil
}
