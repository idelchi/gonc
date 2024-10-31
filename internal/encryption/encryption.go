// Package encryption provides functionality for file encryption and decryption using AES
// in either CBC mode or deterministic encryption using Google Tink. It supports concurrent
// processing of multiple files with configurable parallelism.
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

	"github.com/golang/protobuf/proto"
	"github.com/idelchi/gonc/internal/config"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	aes_sivpb "github.com/tink-crypto/tink-go/v2/proto/aes_siv_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/tink"
	"golang.org/x/sync/errgroup"
)

const (
	// defaultBufferSize defines the size of the buffer used for file I/O operations.
	defaultBufferSize = 32 * 1024 // 32KB default buffer size
)

// bufferPool provides a pool of reusable byte slices for file I/O operations.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, defaultBufferSize)
	},
}

// CipherMode represents the encryption mode to be used (CBC or Deterministic).
type CipherMode byte

const (
	// ModeCBC represents Cipher Block Chaining mode.
	ModeCBC CipherMode = iota
	// ModeDeterministic represents deterministic encryption using Tink.
	ModeDeterministic
)

// Result represents the outcome of processing a single file.
type Result struct {
	Input  string // Input file path
	Output string // Output file path
	Error  error  // Any error that occurred during processing
}

// Processor handles the encryption and decryption of files.
type Processor struct {
	cfg     config.Config          // Configuration for the processor
	cipher  cipher.Block           // AES cipher block
	daead   tink.DeterministicAEAD // Tink Deterministic AEAD primitive
	key     []byte                 // Key bytes for deferred initialization
	results chan Result            // Channel for collecting processing results
}

// NewProcessor creates a new Processor with the given configuration.
// It initializes the AES cipher or stores the key for deferred initialization.
func NewProcessor(cfg config.Config) (*Processor, error) {
	keyBytes, err := hex.DecodeString(cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("decoding key: %w", err)
	}

	if cfg.Decrypt {
		// Defer cipher initialization until after reading the encryption mode
		return &Processor{
			cfg:     cfg,
			key:     keyBytes,
			results: make(chan Result, len(cfg.Files)),
		}, nil
	}

	// Encryption mode is known; initialize cipher or AEAD now
	var (
		block cipher.Block
		d     tink.DeterministicAEAD
	)

	if cfg.Deterministic {
		// Ensure key length is 64 bytes for AES-SIV
		if len(keyBytes) != 64 {
			return nil, fmt.Errorf("key must be 64 bytes (128 hex characters) for AES-SIV")
		}

		// Initialize Deterministic AEAD
		kh, err := newDeterministicAEADKeyHandle(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("creating keyset handle: %w", err)
		}

		d, err = daead.New(kh)
		if err != nil {
			return nil, fmt.Errorf("creating DeterministicAEAD: %w", err)
		}
	} else {
		// Ensure key length is 32 bytes for AES-256
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("key must be 32 bytes (64 hex characters) for AES-256")
		}

		// Initialize AES cipher block for CBC mode
		block, err = aes.NewCipher(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("creating cipher: %w", err)
		}
	}

	return &Processor{
		cfg:     cfg,
		cipher:  block,
		daead:   d,
		results: make(chan Result, len(cfg.Files)),
	}, nil
}

// newDeterministicAEADKeyHandle creates a keyset handle for Deterministic AEAD using the provided key.
func newDeterministicAEADKeyHandle(key []byte) (*keyset.Handle, error) {
	// Create an AesSivKey proto message
	aesSivKey := &aes_sivpb.AesSivKey{
		Version:  0,
		KeyValue: key,
	}

	serializedKey, err := proto.Marshal(aesSivKey)
	if err != nil {
		return nil, fmt.Errorf("serializing AesSivKey: %w", err)
	}

	keyData := &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}

	// Create a Keyset containing the key
	ks := &tinkpb.Keyset{
		PrimaryKeyId: 1,
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData:          keyData,
				Status:           tinkpb.KeyStatusType_ENABLED,
				KeyId:            1,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	// Use insecurecleartextkeyset to create a keyset handle
	kh, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle: %w", err)
	}

	return kh, nil
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
	var (
		mode CipherMode
		err  error
	)

	if p.cfg.Deterministic {
		mode = ModeDeterministic
	} else {
		mode = ModeCBC
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

	if p.cfg.Deterministic {
		err = p.encryptDeterministic(r, w)
	} else {
		err = p.encryptCBC(r, w)
	}

	return err
}

// encryptDeterministic encrypts data using Tink's Deterministic AEAD.
func (p *Processor) encryptDeterministic(r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading input data: %w", err)
	}

	// Encrypt data deterministically
	ciphertext, err := p.daead.EncryptDeterministically(data, nil)
	if err != nil {
		return fmt.Errorf("encrypting data: %w", err)
	}

	// Write ciphertext
	if _, err := w.Write(ciphertext); err != nil {
		return fmt.Errorf("writing encrypted data: %w", err)
	}

	return nil
}

// encryptCBC encrypts data using CBC mode with PKCS#7 padding.
func (p *Processor) encryptCBC(r io.Reader, w io.Writer) error {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("generating IV: %w", err)
	}

	if _, err := w.Write(iv); err != nil {
		return fmt.Errorf("writing IV: %w", err)
	}

	cbcMode := cipher.NewCBCEncrypter(p.cipher, iv)

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	var plaintext []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			plaintext = append(plaintext, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}
	}

	// Pad data to block size
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(padded))
	cbcMode.CryptBlocks(ciphertext, padded)

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

	// Initialize cipher or AEAD based on mode
	var err error
	switch mode {
	case ModeDeterministic:
		// Ensure key length is 64 bytes for AES-SIV
		if len(p.key) != 64 {
			return false, fmt.Errorf("key must be 64 bytes (128 hex characters) for AES-SIV")
		}

		// Initialize Deterministic AEAD
		kh, err := newDeterministicAEADKeyHandle(p.key)
		if err != nil {
			return false, fmt.Errorf("creating keyset handle: %w", err)
		}

		p.daead, err = daead.New(kh)
		if err != nil {
			return false, fmt.Errorf("creating DeterministicAEAD: %w", err)
		}

		err = p.decryptDeterministic(r, w)
	case ModeCBC:
		// Ensure key length is 32 bytes for AES-256
		if len(p.key) != 32 {
			return false, fmt.Errorf("key must be 32 bytes (64 hex characters) for AES-256")
		}

		// Initialize AES cipher block for CBC mode
		p.cipher, err = aes.NewCipher(p.key)
		if err != nil {
			return false, fmt.Errorf("creating cipher: %w", err)
		}

		err = p.decryptCBC(r, w)
	default:
		return false, fmt.Errorf("unknown encryption mode: %d", mode)
	}

	return isExec, err
}

// decryptDeterministic decrypts data encrypted with Tink's Deterministic AEAD.
func (p *Processor) decryptDeterministic(r io.Reader, w io.Writer) error {
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading encrypted data: %w", err)
	}

	// Decrypt data deterministically
	plaintext, err := p.daead.DecryptDeterministically(ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypting data: %w", err)
	}

	// Write plaintext
	if _, err := w.Write(plaintext); err != nil {
		return fmt.Errorf("writing decrypted data: %w", err)
	}

	return nil
}

// decryptCBC decrypts data that was encrypted using CBC mode.
func (p *Processor) decryptCBC(r io.Reader, w io.Writer) error {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(r, iv); err != nil {
		return fmt.Errorf("reading IV: %w", err)
	}

	cbcMode := cipher.NewCBCDecrypter(p.cipher, iv)

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	var ciphertext []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			ciphertext = append(ciphertext, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading encrypted data: %w", err)
		}
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	cbcMode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return err
	}

	if _, err := w.Write(unpadded); err != nil {
		return fmt.Errorf("writing decrypted data: %w", err)
	}

	return nil
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
		// Set output permissions
		perm := os.FileMode(0o600)
		if isExec {
			perm |= 0o111
		}
		if err := os.Chmod(tmpName, perm); err != nil {
			return fmt.Errorf("setting file permissions: %w", err)
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
