package config

import (
	"errors"
	"fmt"

	"github.com/idelchi/gogen/pkg/validator"
)

// ErrUsage indicates an error in command-line usage or configuration.
var ErrUsage = errors.New("usage error")

// Suffixes contains the file suffixes for encrypted and decrypted files.
type Suffixes struct {
	// Suffix for encrypted files
	Encrypt string `mapstructure:"encrypt-ext"`

	// Suffix for decrypted files
	Decrypt string `mapstructure:"decrypt-ext"`
}

// Key contains the encryption key.
type Key struct {
	// Key in hexadecimal format
	String string `label:"--key" mapstructure:"key" mask:"fixed" validate:"omitempty,hexadecimal,len=64|len=128,exclusive=File"` //nolint:lll // struct tags

	// Key in a file
	File string `label:"--key-file" mapstructure:"key-file" validate:"exclusive=String"`
}

// Config contains the application configuration.
type Config struct {
	// Show the configuration and exit
	Show bool

	// Quiet mode
	Quiet bool

	// Delete the original file after successful encryption/decryption
	Delete bool

	// Number of files to process in parallel
	Parallel int

	// Key holds the encryption key as a string or a file
	Key Key `mapstructure:",squash"`

	// Suffixes for encrypted and decrypted files
	Suffixes Suffixes `mapstructure:",squash"`

	// Encryption mode
	Deterministic bool

	// Decrypt files
	Decrypt bool `mapstructure:"-"`

	// Redact mode — replace file contents with fixed string
	Redact bool `mapstructure:"-"`

	// Content string to write when redacting
	Content string `mapstructure:"content"`

	// Inline include glob patterns
	Include []string `mapstructure:"include"`

	// Inline exclude glob patterns
	Exclude []string `mapstructure:"exclude"`

	// Path to JSONC file with include glob patterns
	IncludeFrom string `mapstructure:"include-from"`

	// Path to JSONC file with exclude glob patterns
	ExcludeFrom string `mapstructure:"exclude-from"`

	// Dry run mode — show what would be processed without doing it
	Dry bool

	// Print processing statistics
	Stats bool

	// Preserve original file modification times
	PreserveTimestamps bool `mapstructure:"preserve-timestamps"`

	// Files or directories to process
	Files []string
}

// Display returns the value of the Show field.
func (c Config) Display() bool {
	return c.Show
}

// Validate performs configuration validation using the validator package.
// It returns a wrapped ErrUsage if any validation rules are violated.
func (c Config) Validate(config any) error {
	validator := validator.New()

	if err := registerExclusive(validator); err != nil {
		return fmt.Errorf("registering exclusive: %w", err)
	}

	errs := validator.Validate(config)

	switch {
	case errs == nil:
		return nil
	case len(errs) == 1:
		return fmt.Errorf("%w: %w", ErrUsage, errs[0])
	case len(errs) > 1:
		return fmt.Errorf("%ws:\n%w", ErrUsage, errors.Join(errs...))
	}

	if c.Redact && (c.Key.String != "" || c.Key.File != "") {
		return fmt.Errorf("%w: --key/--key-file cannot be used with redact", ErrUsage)
	}

	return nil
}
