package commands

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/encryption"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewGenerateCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate a new encryption key",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
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
func NewEncryptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "encrypt [flags] files...",
		Aliases: []string{"enc"},
		Short:   "Encrypt files",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Unmarshal all config (from env vars and flags) into struct
			var cfg config.Config
			if err := viper.Unmarshal(&cfg); err != nil {
				return fmt.Errorf("parsing config: %w", err)
			}

			cfg.Files = args

			if err := cfg.Validate(); err != nil {
				return err
			}

			return runProcessor(cfg)
		},
	}
	return cmd
}

func NewDecryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "decrypt [flags] files...",
		Aliases: []string{"dec"},
		Short:   "Decrypt files",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var cfg config.Config
			if err := viper.Unmarshal(&cfg); err != nil {
				return fmt.Errorf("parsing config: %w", err)
			}

			cfg.Files = args
			cfg.Decrypt = true

			if err := cfg.Validate(); err != nil {
				return err
			}

			return runProcessor(cfg)
		},
	}
}

func runProcessor(cfg config.Config) error {
	proc, err := encryption.NewProcessor(cfg)
	if err != nil {
		return fmt.Errorf("creating processor: %w", err)
	}

	return proc.ProcessFiles()
}
