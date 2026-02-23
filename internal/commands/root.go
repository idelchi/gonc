package commands

import (
	"runtime"

	"github.com/spf13/cobra"

	"github.com/idelchi/gogen/pkg/cobraext"
	"github.com/idelchi/gonc/internal/config"
)

// NewRootCommand creates the root command with common configuration.
// It sets up environment variable binding and flag handling.
func NewRootCommand(cfg *config.Config, version string) *cobra.Command {
	root := cobraext.NewDefaultRootCommand(version)

	root.Use = "gonc [flags] command [flags]"
	root.Short = "File encryption utility"
	root.Long = `A file encryption utility that supports deterministic and non-deterministic modes.
Provides commands for key generation, encryption, and decryption.`

	root.Flags().BoolP("show", "s", false, "Show the configuration and exit")
	root.Flags().IntP("parallel", "j", runtime.NumCPU(), "Number of parallel workers, defaults to number of CPUs")
	root.Flags().BoolP("quiet", "q", false, "Suppress non-error output")
	root.Flags().Bool("delete", false, "Delete the original file after successful encryption/decryption")

	root.Flags().StringP("key", "k", "", "Encryption key (64 or 32 bytes, hex-encoded)")
	root.Flags().
		StringP("key-file", "f", "", "Path to the key file with the encryption key (64 or 32 bytes, hex-encoded)")

	root.Flags().String("encrypt-ext", ".enc", "Suffix to append to encrypted files")
	root.Flags().String("decrypt-ext", "", "Suffix to append to decrypted files, after stripping the encrypted suffix")

	root.Flags().StringSlice("include", nil, "Glob patterns to narrow results (repeatable)")
	root.Flags().StringSlice("exclude", nil, "Glob patterns to exclude from results (repeatable)")
	root.Flags().String("include-from", "", "Path to JSONC file with include glob patterns")
	root.Flags().String("exclude-from", "", "Path to JSONC file with exclude glob patterns")

	root.Flags().Bool("dry", false, "Show what would be processed without actually doing it")
	root.Flags().Bool("stats", false, "Print processing statistics after completion")
	root.Flags().Bool("preserve-timestamps", false, "Preserve original file modification times")

	root.AddCommand(NewEncryptCommand(cfg), NewDecryptCommand(cfg), NewRedactCommand(cfg), NewCheckCommand(cfg))

	return root
}
