package commands

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/encryption"
	"github.com/spf13/cobra"
)

func NewGenerateCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate a new encryption key",
		RunE: func(cmd *cobra.Command, args []string) error {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return fmt.Errorf("generating key: %w", err)
			}
			fmt.Println(hex.EncodeToString(key))

			return nil
		},
	}
}

// internal/commands/commands.go
func NewEncryptCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "encrypt [flags] files...",
		Aliases: []string{"enc"},
		Short:   "Encrypt files",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.Files = args

			if err := cfg.Validate(); err != nil {
				return err
			}

			err := runProcessor(cfg)

			fmt.Println("goncilisious decryption")
			return err
		},
	}
	return cmd
}

func NewDecryptCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:     "decrypt [flags] files...",
		Aliases: []string{"dec"},
		Short:   "Decrypt files",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.Files = args
			cfg.Decrypt = true

			if err := cfg.Validate(); err != nil {
				return err
			}

			err := runProcessor(cfg)

			fmt.Println("goncilisious decryption")
			return err
		},
	}
}

func runProcessor(cfg *config.Config) error {
	proc, err := encryption.NewProcessor(*cfg)
	if err != nil {
		return fmt.Errorf("creating processor: %w", err)
	}

	return proc.ProcessFiles()
}
