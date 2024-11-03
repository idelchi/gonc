package config

import (
	"errors"
	"fmt"

	"github.com/idelchi/gogen/pkg/validator"
)

// ErrUsage indicates an error in command-line usage or configuration.
var ErrUsage = errors.New("usage error")

type Suffixes struct {
	Encrypt string `mapstructure:"encrypt-ext"`
	Decrypt string `mapstructure:"decrypt-ext"`
}

type Key struct {
	String string `mask:"fixed" validate:"hexadecimal,len=64,exclusive=File" mapstructure:"key" label:"--key"`
	File   string `validate:"exclusive=String" mapstructure:"key-file" label:"--key-file"`
}

type Config struct {
	// Show the configuration and exit
	Show     bool
	Parallel int

	Key           Key      `mapstructure:",squash"`
	Suffixes      Suffixes `mapstructure:",squash"`
	Deterministic bool
	Decrypt       bool `mapstructure:"-"`

	// Positional arguments
	Files []string `validate:"required"`
}

// Validate performs configuration validation using the validator package.
// It returns a wrapped ErrUsage if any validation rules are violated.
func Validate(config any) error {
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
