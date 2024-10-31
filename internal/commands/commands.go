package commands

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/encryption"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewRootCmd(cfg *config.Config) *cobra.Command {
	root := &cobra.Command{
		Use:   "gonc",
		Short: "File encryption utility",
		Long: `A file encryption utility that supports deterministic and non-deterministic modes.
Provides commands for key generation, encryption, and decryption.`,
		TraverseChildren: true,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Must provide a subcommand. Run 'gonc --help' for usage.")
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Configure Viper to read from environment variables
			viper.SetEnvPrefix("gonc")
			viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

			viper.AutomaticEnv()
			// Bind all flags to viper with command prefix
			if err := viper.BindPFlags(cmd.Root().Flags()); err != nil {
				return fmt.Errorf("failed to bind flags: %w", err)
			}

			if err := viper.BindPFlags(cmd.Flags()); err != nil {
				return fmt.Errorf("failed to bind persistent flags: %w", err)
			}

			// // Unmarshal the config into our struct
			if err := viper.Unmarshal(cfg); err != nil {
				return fmt.Errorf("failed to unmarshal config: %w", err)
			}

			return nil
		},
	}

	root.CompletionOptions.DisableDefaultCmd = true

	root.SetVersionTemplate("{{ .Version }}\n")

	return root
}

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

			fmt.Println("goncilisious encryption")
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
