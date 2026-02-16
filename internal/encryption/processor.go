package encryption

import (
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
	"github.com/idelchi/gonc/internal/fileutil"
)

// Processor handles the encryption and decryption of files.
type Processor struct {
	// cfg contains runtime configuration options
	cfg *config.Config

	// daead provides deterministic authenticated encryption
	daead tink.DeterministicAEAD

	// key stores raw key bytes
	key []byte

	// results channels processing outcomes to the printer goroutine
	results chan Result
}

const (
	// AesSivKeySize is the required key size for AES-SIV encryption.
	AesSivKeySize = 64
	// AesKeySize is the required key size for randomized encryption.
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

	processor := &Processor{
		cfg:     cfg,
		key:     encryptionKey,
		results: make(chan Result, len(cfg.Files)),
	}

	if cfg.Decrypt {
		if len(encryptionKey) != AesSivKeySize && len(encryptionKey) != AesKeySize {
			return nil, errors.New("decrypt: key must be 32 or 64 bytes (64 or 128 hex characters)")
		}

		return processor, nil
	}

	if cfg.Deterministic { //nolint:nestif
		if len(encryptionKey) != AesSivKeySize {
			return nil, errors.New("encrypt: deterministic mode requires 64-byte key (128 hex characters)")
		}

		kh, err := newDeterministicAEADKeyHandle(encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("creating keyset handle: %w", err)
		}

		daeadPrimitive, err := daead.New(kh)
		if err != nil {
			return nil, fmt.Errorf("creating DeterministicAEAD: %w", err)
		}

		processor.daead = daeadPrimitive
	} else { //nolint:gocritic
		if len(encryptionKey) != AesKeySize {
			return nil, errors.New("encrypt: randomized mode requires 32-byte key (64 hex characters)")
		}
	}

	return processor, nil
}

// ProcessFiles concurrently processes all files specified in the configuration.
// It encrypts or decrypts files based on the configuration settings.
// Returns the number of successfully processed files and the number of errors.
//
//nolint:cyclop,gocognit
func (p *Processor) ProcessFiles() (processed, errored int, totalSize int64, err error) {
	group := errgroup.Group{}
	group.SetLimit(p.cfg.Parallel)

	done := make(chan struct{})

	go func() {
		defer close(done)

		for result := range p.results {
			if result.Error != nil {
				errored++

				fmt.Fprintf(os.Stderr, "Error processing %q: %v\n", result.Input, result.Error)
			} else {
				processed++

				totalSize += result.OutputSize

				if !p.cfg.Quiet {
					fmt.Printf("Processed %q -> %q\n", result.Input, result.Output) //nolint:forbidigo
				}
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

			size, err := p.processFile(file, outPath)
			if err != nil {
				p.results <- Result{Input: file, Error: err}

				return err
			}

			p.results <- Result{Input: file, Output: outPath, OutputSize: size}

			return nil
		})
	}

	err = group.Wait()

	close(p.results)

	<-done // Wait for printer to finish

	if err != nil {
		return processed, errored, totalSize, fmt.Errorf("processing files: %w", err)
	}

	return processed, errored, totalSize, nil
}

// encrypt reads data from r, encrypts it using the configured mode,
// and writes the result to w. The isExec parameter preserves the executable bit information.
func (p *Processor) encrypt(reader io.Reader, writer io.Writer, isExec bool) error {
	var (
		mode envelopeMode
		err  error
	)

	if p.cfg.Deterministic {
		mode = modeDeterministic
	} else {
		mode = modeRandomized
	}

	header := newEnvelopeHeader(mode, isExec)
	if _, err := writer.Write(header); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	if p.cfg.Deterministic {
		err = p.encryptDeterministic(reader, writer, header)
	} else {
		err = p.encryptRandomized(reader, writer, header)
	}

	return err
}

// decrypt reads encrypted data from r, decrypts it using the mode specified in the header,
// and writes the result to w. It returns whether the original file was executable.
func (p *Processor) decrypt(reader io.Reader, writer io.Writer) (bool, error) {
	header := make([]byte, envelopeHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return false, fmt.Errorf("reading header: %w", err)
	}

	mode, exec, err := parseEnvelopeHeader(header)
	if err != nil {
		return false, err
	}

	switch mode {
	case modeDeterministic:
		if len(p.key) != AesSivKeySize {
			return false, errors.New("decrypt: deterministic data requires 64-byte key (128 hex characters)")
		}

		if p.daead == nil {
			kh, err := newDeterministicAEADKeyHandle(p.key)
			if err != nil {
				return false, fmt.Errorf("creating keyset handle: %w", err)
			}

			daeadPrimitive, err := daead.New(kh)
			if err != nil {
				return false, fmt.Errorf("creating DeterministicAEAD: %w", err)
			}

			p.daead = daeadPrimitive
		}

		return exec, p.decryptDeterministic(reader, writer, header)
	case modeRandomized:
		if len(p.key) != AesKeySize {
			return false, errors.New("decrypt: randomized data requires 32-byte key (64 hex characters)")
		}

		return exec, p.decryptRandomized(reader, writer, header)
	default:
		return false, errors.New("unknown encryption mode")
	}
}

// processFile handles the encryption or decryption of a single file.
// It creates a temporary file for output and performs an atomic rename on completion.
//
//nolint:funlen,cyclop,gocognit
func (p *Processor) processFile(filename, outPath string) (size int64, err error) {
	tc, err := fileutil.NewTempContext(filename, outPath)
	if err != nil {
		return 0, fmt.Errorf("preparing atomic write: %w", err)
	}

	defer tc.CleanupOnError(&err)

	inFile, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return 0, fmt.Errorf("opening input file: %w", err)
	}
	defer inFile.Close()

	const ownerReadWrite = 0o600

	if p.cfg.Decrypt { //nolint:nestif
		execOut, err := p.decrypt(inFile, tc.TmpFile)
		if err != nil {
			return 0, fmt.Errorf("decrypting file: %w", err)
		}

		perm := os.FileMode(ownerReadWrite)

		if execOut {
			perm |= 0o111
		}

		if err := os.Chmod(tc.TmpName, perm); err != nil {
			return 0, fmt.Errorf("setting file permissions: %w", err)
		}
	} else {
		if err := p.encrypt(inFile, tc.TmpFile, tc.IsExec); err != nil {
			return 0, fmt.Errorf("encrypting file: %w", err)
		}

		perm := os.FileMode(ownerReadWrite)

		if tc.IsExec {
			perm |= 0o111
		}

		if err := os.Chmod(tc.TmpName, perm); err != nil {
			return 0, fmt.Errorf("setting file permissions: %w", err)
		}
	}

	if err := tc.TmpFile.Close(); err != nil {
		return 0, fmt.Errorf("closing temporary file: %w", err)
	}

	if err := inFile.Close(); err != nil {
		return 0, fmt.Errorf("closing input file: %w", err)
	}

	if err := os.Rename(tc.TmpName, outPath); err != nil {
		return 0, fmt.Errorf("renaming output file: %w", err)
	}

	size, err = fileutil.FinalizeOutput(outPath, p.cfg.PreserveTimestamps, tc.SrcInfo.ModTime())
	if err != nil {
		return 0, fmt.Errorf("finalizing output: %w", err)
	}

	return size, nil
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
