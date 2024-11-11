package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/idelchi/gogen/pkg/cobraext"
	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/logic"
)

// NewDecryptCommand creates a new cobra command for the decrypt subcommand.
func NewDecryptCommand(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:     "decrypt [flags] files...",
		Aliases: []string{"dec"},
		Short:   "Decrypt files",
		Args:    cobra.MinimumNArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			cfg.Files = args
			cfg.Decrypt = true

			return cobraext.Validate(cfg, cfg)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := logic.Run(cfg); err != nil {
				return fmt.Errorf("running logic: %w", err)
			}

			return nil
		},
	}
}
