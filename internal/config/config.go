package config

import (
	"encoding/hex"
	"fmt"

	"github.com/go-playground/validator/v10"
)

type Config struct {
	// Common flags
	Key           string `validate:"required,len=64"` // hex encoded, so 32 bytes = 64 chars
	Parallel      int
	EncryptSuffix string `mapstructure:"encrypt-ext"`
	DecryptSuffix string `mapstructure:"decrypt-ext"`

	// Command-specific flags
	Deterministic bool
	Decrypt       bool

	// Positional arguments
	Files []string `validate:"min=1"`
}

// Validate validates the configuration against the struct tags
func (c Config) Validate() error {
	validate := validator.New()

	if err := validate.Struct(c); err != nil {
		return fmt.Errorf("validating configuration: %w", err)
	}

	// Additional key validation
	if _, err := hex.DecodeString(c.Key); err != nil {
		return fmt.Errorf("invalid key format: %w", err)
	}

	return nil
}
