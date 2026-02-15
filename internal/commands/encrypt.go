package commands

import (
	"github.com/spf13/cobra"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/logic"
)

// NewEncryptCommand creates a new cobra command for the encrypt subcommand.
func NewEncryptCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "encrypt [flags] [paths/patterns...]",
		Aliases: []string{"enc"},
		Short:   "Encrypt files",
		Args:    cobra.ArbitraryArgs,
		PreRunE: preRun(cfg),
		RunE: func(_ *cobra.Command, _ []string) error {
			return logic.Run(cfg)
		},
	}

	cmd.Flags().BoolP("deterministic", "d", false, "Use deterministic encryption mode")

	return cmd
}
