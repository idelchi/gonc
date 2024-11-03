package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/tink"

	"github.com/idelchi/gogen/pkg/key"
	"github.com/idelchi/gonc/internal/config"
)

// Processor handles the encryption and decryption of files.
type Processor struct {
	cfg     *config.Config         // Configuration for the processor
	cipher  cipher.Block           // AES cipher block
	daead   tink.DeterministicAEAD // Tink Deterministic AEAD primitive
	key     []byte                 // Key bytes for deferred initialization
	results chan Result            // Channel for collecting processing results
}

const (
	AES_SIV_KEY_SIZE = 64
	AES_KEY_SIZE     = 32
)

// NewProcessor creates a new Processor with the given configuration.
// It initializes the AES cipher or stores the key for deferred initialization.
func NewProcessor(cfg *config.Config) (*Processor, error) {
	var (
		encryptionKey []byte
		err           error
	)

	switch {
	case cfg.Key.String != "":
		encryptionKey, err = key.FromHex(cfg.Key.String)
	case cfg.Key.File != "":
		encryptionKey, err = os.ReadFile(cfg.Key.File)
		if err != nil {
			return nil, fmt.Errorf("reading key file: %w", err)
		}

		encryptionKey, err = key.FromHex(string(encryptionKey))
	}

	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}

	if cfg.Decrypt {
		// Defer cipher initialization until after reading the encryption mode
		return &Processor{
			cfg:     cfg,
			key:     encryptionKey,
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
		if len(encryptionKey) != AES_SIV_KEY_SIZE {
			return nil, fmt.Errorf("NewProcessor: key must be 64 bytes (128 hex characters) for AES-SIV")
		}

		// Initialize Deterministic AEAD
		kh, err := newDeterministicAEADKeyHandle(encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("creating keyset handle: %w", err)
		}

		d, err = daead.New(kh)
		if err != nil {
			return nil, fmt.Errorf("creating DeterministicAEAD: %w", err)
		}
	} else {
		// Ensure key length is 32 bytes for AES-256
		if len(encryptionKey) != AES_KEY_SIZE {
			return nil, fmt.Errorf("NewProcessor: key must be 32 bytes (64 hex characters) for AES-256")
		}

		// Initialize AES cipher block for CBC mode
		block, err = aes.NewCipher(encryptionKey)
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

// ProcessFiles concurrently processes all files specified in the configuration.
// It encrypts or decrypts files based on the configuration settings.
func (p *Processor) ProcessFiles() error {
	g := new(errgroupWrapper)
	g.SetLimit(p.cfg.Parallel)

	// Start result printer
	done := make(chan struct{})
	go func() {
		defer close(done)
		for result := range p.results {
			if result.Error != nil {
				fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", result.Input, result.Error)
			} else {
				fmt.Printf("Processed %q -> %q\n", result.Input, result.Output)
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

// decrypt reads encrypted data from r, decrypts it using the mode specified in the header,
// and writes the result to w. It returns whether the original file was executable.
func (p *Processor) decrypt(reader io.Reader, writer io.Writer) (bool, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return false, fmt.Errorf("reading header: %w", err)
	}

	mode := CipherMode(header[0])
	isExec := header[1] == 1

	// Initialize cipher or AEAD based on mode
	switch mode {
	case ModeDeterministic:
		// Ensure key length is 64 bytes for AES-SIV
		if len(p.key) != AES_SIV_KEY_SIZE {
			return false, fmt.Errorf("decrypt: key must be 64 bytes (128 hex characters) for AES-SIV")
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

		return isExec, p.decryptDeterministic(reader, writer)
	case ModeCBC:
		// Ensure key length is 32 bytes for AES-256
		if len(p.key) != AES_KEY_SIZE {
			return false, fmt.Errorf("decrypt: key must be 32 bytes (64 hex characters) for AES-256")
		}

		var err error

		// Initialize AES cipher block for CBC mode
		p.cipher, err = aes.NewCipher(p.key)
		if err != nil {
			return false, fmt.Errorf("creating cipher: %w", err)
		}

		return isExec, p.decryptCBC(reader, writer)
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

	const EXECUTABLE_BITS = 0o111

	isExec := info.Mode()&EXECUTABLE_BITS != 0

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
			return fmt.Errorf("decrypting file: %w", err)
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
			return fmt.Errorf("encrypting file: %w", err)
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
	ext := p.cfg.Suffixes.Encrypt
	if p.cfg.Decrypt {
		filename = strings.TrimSuffix(filename, p.cfg.Suffixes.Encrypt)
		ext = p.cfg.Suffixes.Decrypt
	}

	return filepath.Join(filepath.Dir(filename),
		filepath.Base(filename)+ext)
}
