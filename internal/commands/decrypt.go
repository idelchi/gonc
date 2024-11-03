package commands

import (
	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/logic"
	"github.com/spf13/cobra"
)

func NewDecryptCommand(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:     "decrypt [flags] files...",
		Aliases: []string{"dec"},
		Short:   "Decrypt files",
		Args:    cobra.MinimumNArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			cfg.Files = args
			cfg.Decrypt = true

			return validate(cfg, cfg)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := logic.Run(cfg)

			return err
		},
	}
}
