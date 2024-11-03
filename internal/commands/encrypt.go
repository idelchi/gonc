package commands

import (
	"github.com/spf13/cobra"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/logic"
)

func NewEncryptCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "encrypt [flags] files...",
		Aliases: []string{"enc"},
		Short:   "Encrypt files",
		Args:    cobra.MinimumNArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			cfg.Files = args

			return validate(cfg, cfg)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return logic.Run(cfg)
		},
	}
	return cmd
}
