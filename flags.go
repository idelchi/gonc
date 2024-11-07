package main

import (
	"github.com/spf13/cobra"

	"github.com/idelchi/gonc/internal/commands"
	"github.com/idelchi/gonc/internal/config"
)

// flags creates and configures the command-line interface.
// It returns the root command with all subcommands and flags configured.
func flags() *cobra.Command {
	cfg := &config.Config{}
	root := commands.NewRootCommand(cfg, version)

	return root
}
