package commands

import (
	"github.com/spf13/cobra"

	"github.com/idelchi/gogen/pkg/cobraext"
	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/logic"
)

// NewEncryptCommand creates a new cobra command for the encrypt subcommand.
func NewEncryptCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "encrypt [flags] files...",
		Aliases: []string{"enc"},
		Short:   "Encrypt files",
		Args:    cobra.MinimumNArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			cfg.Files = args

			return cobraext.Validate(cfg, cfg)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return logic.Run(cfg)
		},
	}

	cmd.Flags().BoolP("deterministic", "d", false, "Use deterministic encryption mode")

	return cmd
}
