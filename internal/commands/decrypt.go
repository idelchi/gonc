package commands

import (
	"github.com/spf13/cobra"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/logic"
)

// NewDecryptCommand creates a new cobra command for the decrypt subcommand.
func NewDecryptCommand(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:     "decrypt [flags] [paths/patterns...]",
		Aliases: []string{"dec"},
		Short:   "Decrypt files",
		Args:    cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			cfg.Decrypt = true

			return preRun(cfg)(cmd, args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return logic.Run(cfg)
		},
	}
}
