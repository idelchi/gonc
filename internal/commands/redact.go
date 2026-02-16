package commands

import (
	"github.com/spf13/cobra"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/logic"
)

// NewRedactCommand creates a new cobra command for the redact subcommand.
func NewRedactCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "redact [flags] [paths/patterns...]",
		Aliases: []string{"red"},
		Short:   "Replace file contents with a fixed string",
		Args:    cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			cfg.Redact = true

			return preRun(cfg)(cmd, args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return logic.RunRedact(cfg)
		},
	}

	cmd.Flags().String("content", "<REDACTED>", "Replacement content for redacted files")

	return cmd
}
