package encryption

import (
	"bufio"
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

type CipherMode byte

const (
	ModeCBC CipherMode = iota
	ModeECB
)

const (
	chunkSize    = 1 * 1024 * 1024 // 1MB chunks
	resultBuffer = 1000            // Buffer size for result channel
)

type Processor struct {
	cfg     config.Config
	cipher  cipher.Block
	results chan Result
	pool    sync.Pool
}

type Result struct {
	Input  string
	Output string
	Error  error
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
		results: make(chan Result, resultBuffer),
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, chunkSize+aes.BlockSize)
			},
		},
	}, nil
}

func (p *Processor) ProcessFiles() error {
	g := new(errgroup.Group)
	g.SetLimit(p.cfg.Parallel)

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

	for _, file := range p.cfg.Files {
		file := file
		g.Go(func() error {
			outPath := p.outputPath(file)
			if err := p.processFileStreaming(file, outPath); err != nil {
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

func (p *Processor) processFileStreaming(inPath, outPath string) error {
	info, err := os.Stat(inPath)
	if err != nil {
		return fmt.Errorf("getting file info: %w", err)
	}

	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("opening input file: %w", err)
	}
	defer inFile.Close()

	// Create temporary writer to capture output
	var buf bytes.Buffer
	bufOut := bufio.NewWriter(&buf)

	var isExec bool
	if p.cfg.Decrypt {
		// For decryption, get executable bit from header
		var err error
		isExec, err = p.processDecryptStream(inFile, bufOut)
		if err != nil {
			return err
		}
	} else {
		// For encryption, get executable bit from input file
		isExec = info.Mode()&0o111 != 0
		if err := p.processEncryptStream(inFile, bufOut, isExec); err != nil {
			return err
		}
	}

	if err := bufOut.Flush(); err != nil {
		return fmt.Errorf("flushing buffer: %w", err)
	}

	// Set permissions based on operation type and executable bit
	perm := os.FileMode(0o600)
	if isExec {
		perm |= 0o111
	}

	// Write to output file with correct permissions
	if err := os.WriteFile(outPath, buf.Bytes(), perm); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}

	return nil
}

func (p *Processor) processEncryptStream(r io.Reader, w *bufio.Writer, isExec bool) error {
	mode := ModeCBC
	if p.cfg.Deterministic {
		mode = ModeECB
	}
	header := []byte{byte(mode)}
	if isExec {
		header = append(header, 1)
	} else {
		header = append(header, 0)
	}
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	var iv []byte
	if mode == ModeCBC {
		iv = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return fmt.Errorf("generating IV: %w", err)
		}
		if _, err := w.Write(iv); err != nil {
			return fmt.Errorf("writing IV: %w", err)
		}
	}

	buf := p.pool.Get().([]byte)
	defer p.pool.Put(buf)

	var encrypter cipher.BlockMode
	if mode == ModeCBC {
		encrypter = cipher.NewCBCEncrypter(p.cipher, iv)
	}

	var remainder []byte
	for {
		n, err := r.Read(buf[len(remainder):chunkSize])
		if n == 0 && err == io.EOF {
			break
		}
		if err != nil && err != io.EOF {
			return fmt.Errorf("reading input: %w", err)
		}

		chunk := buf[:n+len(remainder)]
		if err == io.EOF {
			chunk = pkcs7Pad(chunk, aes.BlockSize)
		}

		if len(chunk)%aes.BlockSize != 0 {
			remainder = chunk
			continue
		}

		if mode == ModeCBC {
			encrypter.CryptBlocks(chunk, chunk)
		} else {
			p.encryptECBInPlace(chunk)
		}

		if _, err := w.Write(chunk); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		remainder = nil
	}

	return nil
}

func (p *Processor) processDecryptStream(r io.Reader, w *bufio.Writer) (bool, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return false, fmt.Errorf("reading header: %w", err)
	}

	mode := CipherMode(header[0])
	isExec := header[1] == 1

	var iv []byte
	if mode == ModeCBC {
		iv = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(r, iv); err != nil {
			return false, fmt.Errorf("reading IV: %w", err)
		}
	}

	buf := p.pool.Get().([]byte)
	defer p.pool.Put(buf)

	var decrypter cipher.BlockMode
	if mode == ModeCBC {
		decrypter = cipher.NewCBCDecrypter(p.cipher, iv)
	}

	var lastChunk []byte
	for {
		n, err := r.Read(buf[:chunkSize])
		if n == 0 && err == io.EOF {
			break
		}
		if err != nil && err != io.EOF {
			return false, fmt.Errorf("reading input: %w", err)
		}

		chunk := buf[:n]
		if len(chunk)%aes.BlockSize != 0 {
			return false, fmt.Errorf("invalid encrypted data length")
		}

		if mode == ModeCBC {
			decrypter.CryptBlocks(chunk, chunk)
		} else {
			p.decryptECBInPlace(chunk)
		}

		if err != io.EOF {
			if lastChunk != nil {
				if _, err := w.Write(lastChunk); err != nil {
					return false, fmt.Errorf("writing output: %w", err)
				}
			}
			lastChunk = make([]byte, len(chunk))
			copy(lastChunk, chunk)
			continue
		}

		if lastChunk != nil {
			if _, err := w.Write(lastChunk); err != nil {
				return false, fmt.Errorf("writing output: %w", err)
			}
		}

		unpadded, err := pkcs7Unpad(chunk)
		if err != nil {
			return false, fmt.Errorf("removing padding: %w", err)
		}

		if _, err := w.Write(unpadded); err != nil {
			return false, fmt.Errorf("writing final output: %w", err)
		}
	}

	return isExec, nil
}

func (p *Processor) encryptECBInPlace(data []byte) {
	size := p.cipher.BlockSize()
	for i := 0; i < len(data); i += size {
		p.cipher.Encrypt(data[i:i+size], data[i:i+size])
	}
}

func (p *Processor) decryptECBInPlace(data []byte) {
	size := p.cipher.BlockSize()
	for i := 0; i < len(data); i += size {
		p.cipher.Decrypt(data[i:i+size], data[i:i+size])
	}
}

func (p *Processor) outputPath(filename string) string {
	ext := p.cfg.EncryptSuffix
	if p.cfg.Decrypt {
		filename = strings.TrimSuffix(filename, p.cfg.EncryptSuffix)
		ext = p.cfg.DecryptSuffix
	}
	return filepath.Join(filepath.Dir(filename),
		filepath.Base(filename)+ext)
}

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

	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:length-padding], nil
}
