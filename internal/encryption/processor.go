package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/tink"

	"github.com/idelchi/gogen/pkg/key"
	"github.com/idelchi/gonc/internal/config"
)

// Processor handles the encryption and decryption of files.
type Processor struct {
	// cfg contains runtime configuration options
	cfg *config.Config

	// cipher holds the AES block cipher for CBC mode
	cipher cipher.Block

	// daead provides deterministic authenticated encryption
	daead tink.DeterministicAEAD

	// key stores raw key bytes for deferred cipher initialization
	key []byte

	// results channels processing outcomes to the printer goroutine
	results chan Result
}

const (
	// AesSivKeySize is the required key size for AES-SIV encryption.
	AesSivKeySize = 64
	// AesKeySize is the required key size for AES-256 encryption.
	AesKeySize = 32
)

// NewProcessor creates a new Processor with the given configuration.
// It initializes the AES cipher or stores the key for deferred initialization.
//
//nolint:funlen,cyclop
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
		block             cipher.Block
		deterministicAEAD tink.DeterministicAEAD
	)

	if cfg.Deterministic { //nolint:nestif
		// Ensure key length is 64 bytes for AES-SIV
		if len(encryptionKey) != AesSivKeySize {
			return nil, errors.New( //nolint:err113
				"NewProcessor: key must be 64 bytes (128 hex characters) for AES-SIV",
			)
		}

		// Initialize Deterministic AEAD
		kh, err := newDeterministicAEADKeyHandle(encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("creating keyset handle: %w", err)
		}

		deterministicAEAD, err = daead.New(kh)
		if err != nil {
			return nil, fmt.Errorf("creating DeterministicAEAD: %w", err)
		}
	} else {
		// Ensure key length is 32 bytes for AES-256
		if len(encryptionKey) != AesKeySize {
			return nil, errors.New("key must be 32 bytes (64 hex characters) for AES-256") //nolint:err113
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
		daead:   deterministicAEAD,
		results: make(chan Result, len(cfg.Files)),
	}, nil
}

// ProcessFiles concurrently processes all files specified in the configuration.
// It encrypts or decrypts files based on the configuration settings.
//
//nolint:cyclop
func (p *Processor) ProcessFiles() error {
	group := errgroup.Group{}
	group.SetLimit(p.cfg.Parallel)

	done := make(chan struct{})

	go func() {
		defer close(done)

		for result := range p.results {
			if result.Error != nil {
				fmt.Fprintf(os.Stderr, "Error processing %q: %v\n", result.Input, result.Error)
			} else if !p.cfg.Quiet {
				fmt.Printf("Processed %q -> %q\n", result.Input, result.Output) //nolint:forbidigo
			}

			if p.cfg.Delete && result.Error == nil {
				if err := os.Remove(result.Input); err != nil {
					fmt.Fprintf(os.Stderr, "Error deleting %q: %v\n", result.Input, err)
				}

				if !p.cfg.Quiet {
					fmt.Printf("Deleted %q\n", result.Input) //nolint:forbidigo
				}
			}
		}
	}()

	for _, file := range p.cfg.Files {
		group.Go(func() error {
			outPath := p.outputPath(file)
			if err := p.processFile(file, outPath); err != nil {
				p.results <- Result{Input: file, Error: err}

				return err
			}
			p.results <- Result{Input: file, Output: outPath}

			return nil
		})
	}

	err := group.Wait()

	close(p.results)

	<-done // Wait for printer to finish

	if err != nil {
		return fmt.Errorf("processing files: %w", err)
	}

	return nil
}

// encrypt reads data from r, encrypts it using the configured mode,
// and writes the result to w. The isExec parameter preserves the executable bit information.
func (p *Processor) encrypt(reader io.Reader, writer io.Writer, isExec bool) error {
	var (
		mode CipherMode
		err  error
	)

	if p.cfg.Deterministic {
		mode = ModeDeterministic
	} else {
		mode = ModeCBC
	}

	header := []byte{byte(mode)}
	if isExec {
		header = append(header, 1)
	} else {
		header = append(header, 0)
	}

	if _, err := writer.Write(header); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	if p.cfg.Deterministic {
		err = p.encryptDeterministic(reader, writer)
	} else {
		err = p.encryptCBC(reader, writer)
	}

	return err
}

// decrypt reads encrypted data from r, decrypts it using the mode specified in the header,
// and writes the result to w. It returns whether the original file was executable.
func (p *Processor) decrypt(reader io.Reader, writer io.Writer) (bool, error) {
	const headerSize = 2

	header := make([]byte, headerSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return false, fmt.Errorf("reading header: %w", err)
	}

	mode := CipherMode(header[0])
	isExec := header[1] == 1

	switch mode {
	case ModeDeterministic:
		if len(p.key) != AesSivKeySize {
			return false, errors.New("decrypt: key must be 64 bytes (128 hex characters) for AES-SIV") //nolint:err113
		}

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
		if len(p.key) != AesKeySize {
			return false, errors.New("decrypt: key must be 32 bytes (64 hex characters) for AES-256") //nolint:err113
		}

		var err error

		p.cipher, err = aes.NewCipher(p.key)
		if err != nil {
			return false, fmt.Errorf("creating cipher: %w", err)
		}

		return isExec, p.decryptCBC(reader, writer)
	default:
		return false, fmt.Errorf("unknown encryption mode: %d", mode) //nolint:err113
	}
}

// processFile handles the encryption or decryption of a single file.
// It creates a temporary file for output and performs an atomic rename on completion.
//
//nolint:funlen,cyclop
func (p *Processor) processFile(filename, outPath string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("getting file info for %q: %w", filename, err)
	}

	const executableBits = 0o111
	isExec := info.Mode()&executableBits != 0

	tmpFile, err := os.CreateTemp(filepath.Dir(outPath), ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}

	tmpName := tmpFile.Name()

	defer func() {
		tmpFile.Close() //nolint:gosec

		if err != nil {
			os.Remove(tmpName) //nolint:gosec
		}
	}()

	inFile, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return fmt.Errorf("opening input file: %w", err)
	}
	defer inFile.Close()

	const ownerReadWrite = 0o600

	if p.cfg.Decrypt { //nolint:nestif
		execOut, err := p.decrypt(inFile, tmpFile)
		if err != nil {
			return fmt.Errorf("decrypting file: %w", err)
		}

		perm := os.FileMode(ownerReadWrite)
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

		perm := os.FileMode(ownerReadWrite)

		if isExec {
			perm |= 0o111
		}

		if err := os.Chmod(tmpName, perm); err != nil {
			return fmt.Errorf("setting file permissions: %w", err)
		}
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temporary file: %w", err)
	}

	if err := inFile.Close(); err != nil {
		return fmt.Errorf("closing input file: %w", err)
	}

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
