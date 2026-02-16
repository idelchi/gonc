// Package commands provides the command-line interface for the gonc tool.
//
// It implements commands for:
//   - encryption
//   - decryption
//   - redaction
//
// The package handles command-line parsing, configuration validation,
// and environment variable binding through cobra and viper.
package commands

import (
	"github.com/spf13/cobra"

	"github.com/idelchi/gogen/pkg/cobraext"
	"github.com/idelchi/gonc/internal/config"
)

// preRun returns a PreRunE handler that resolves positional args into cfg.Files
// and validates the configuration.
func preRun(cfg *config.Config) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, args []string) error {
		if len(args) == 0 {
			cfg.Files = []string{"."}
		} else {
			cfg.Files = args
		}

		return cobraext.Validate(cfg, cfg)
	}
}
