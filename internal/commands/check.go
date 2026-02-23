package commands

import (
	"github.com/spf13/cobra"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/logic"
)

// NewCheckCommand creates a new cobra command for the check subcommand.
func NewCheckCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "check [flags] [paths/patterns...]",
		Short:   "Validate that include/exclude patterns match files",
		Args:    cobra.ArbitraryArgs,
		PreRunE: preRun(cfg),
		RunE: func(_ *cobra.Command, _ []string) error {
			return logic.RunCheck(cfg)
		},
	}

	return cmd
}
