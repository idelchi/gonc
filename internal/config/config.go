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
	String string `label:"--key" mapstructure:"key" mask:"fixed" validate:"hexadecimal,len=64|len=128,exclusive=File"`

	// Key in a file
	File string `label:"--key-file" mapstructure:"key-file" validate:"exclusive=String"`
}

// Config contains the application configuration.
type Config struct {
	// Show the configuration and exit
	Show bool

	// Quiet mode
	Quiet bool

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

	// Files to process
	Files []string `validate:"required"`
}

// Display returns the value of the Show field.
func (c Config) Display() bool {
	return c.Show
}

// Validate performs configuration validation using the validator package.
// It returns a wrapped ErrUsage if any validation rules are violated.
func (c Config) Validate(config any) error {
	validator := validator.NewValidator()

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

	return nil
}
