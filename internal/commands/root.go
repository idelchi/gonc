package commands

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/idelchi/gonc/internal/config"
)

// NewRootCommand creates the root command with common configuration.
// It sets up environment variable binding and flag handling.
func NewRootCommand(cfg *config.Config, version string) *cobra.Command {
	root := &cobra.Command{
		Version: version,
		Use:     "gonc",
		Short:   "File encryption utility",
		Long: `A file encryption utility that supports deterministic and non-deterministic modes.
Provides commands for key generation, encryption, and decryption.`,
		TraverseChildren: true,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("Must provide a subcommand. Run 'gonc --help' for usage.") //nolint: forbidigo
		},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			viper.SetEnvPrefix(cmd.Root().Name())
			viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
			viper.AutomaticEnv()

			if err := viper.BindPFlags(cmd.Root().Flags()); err != nil {
				return fmt.Errorf("binding root flags: %w", err)
			}

			if err := viper.BindPFlags(cmd.Flags()); err != nil {
				return fmt.Errorf("binding command flags: %w", err)
			}

			return nil
		},
	}

	root.Flags().BoolP("show", "s", false, "Show the configuration and exit")
	root.Flags().IntP("parallel", "j", runtime.NumCPU(), "Number of parallel workers, defaults to number of CPUs")

	root.Flags().StringP("key", "k", "", "Encryption key (64 or 32 bytes, hex-encoded)")
	root.Flags().
		StringP("key-file", "f", "", "Path to the key file with the encryption key (64 or 32 bytes, hex-encoded)")
	root.Flags().BoolP("deterministic", "d", false, "Use deterministic encryption mode")

	root.Flags().String("encrypt-ext", ".enc", "Suffix to append to encrypted files")
	root.Flags().String("decrypt-ext", "", "Suffix to append to decrypted files, after stripping the encrypted suffix")

	root.AddCommand(NewEncryptCommand(cfg), NewDecryptCommand(cfg))

	root.CompletionOptions.DisableDefaultCmd = true
	root.Flags().SortFlags = false

	root.SetVersionTemplate("{{ .Version }}\n")

	return root
}
