// Package logic implements the core business logic for the encryption/decryption.
package logic

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dustin/go-humanize"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/encryption"
	"github.com/idelchi/gonc/internal/filter"
)

// Run is the main logic of the application.
func Run(cfg *config.Config) error {
	start := time.Now()

	scanned, err := resolveFiles(cfg)
	if err != nil {
		return fmt.Errorf("resolving files: %w", err)
	}

	excluded := scanned - len(cfg.Files)

	if cfg.Dry {
		return dryRun(cfg, scanned, excluded, start)
	}

	proc, err := encryption.NewProcessor(cfg)
	if err != nil {
		return fmt.Errorf("creating processor: %w", err)
	}

	processed, errored, totalSize, err := proc.ProcessFiles()

	if cfg.Stats {
		printStats(scanned, excluded, processed, errored, totalSize, time.Since(start))
	}

	if err != nil {
		return fmt.Errorf("running logic: %w", err)
	}

	return nil
}

// resolveFiles normalizes positional args, expands globs, and applies include/exclude filtering.
// Returns the total number of files scanned before filtering.
func resolveFiles(cfg *config.Config) (int, error) {
	includes := append([]string{}, cfg.Include...)
	excludes := append([]string{}, cfg.Exclude...)

	if cfg.IncludeFrom != "" {
		patterns, err := filter.LoadPatterns(cfg.IncludeFrom)
		if err != nil {
			return 0, fmt.Errorf("loading include patterns: %w", err)
		}

		includes = append(includes, patterns...)
	}

	if cfg.ExcludeFrom != "" {
		patterns, err := filter.LoadPatterns(cfg.ExcludeFrom)
		if err != nil {
			return 0, fmt.Errorf("loading exclude patterns: %w", err)
		}

		excludes = append(excludes, patterns...)
	}

	hasIncludes := len(cfg.Include) > 0 || cfg.IncludeFrom != ""

	if cfg.Decrypt && !hasIncludes {
		includes = append(includes, "*"+cfg.Suffixes.Encrypt)
		hasIncludes = true
	}

	files, scanned, err := filter.Resolve(cfg.Files, includes, excludes, hasIncludes)
	if err != nil {
		return scanned, fmt.Errorf("filtering files: %w", err)
	}

	cfg.Files = files

	return scanned, nil
}

// dryRun previews what would be processed without actually encrypting/decrypting.
func dryRun(cfg *config.Config, scanned, excluded int, start time.Time) error {
	var totalSize int64

	processed := len(cfg.Files)

	for _, file := range cfg.Files {
		if !cfg.Quiet {
			fmt.Printf("Processed %q -> %q\n", file, outputPath(file, cfg)) //nolint:forbidigo
		}

		if cfg.Stats {
			if info, err := os.Stat(file); err == nil {
				totalSize += info.Size()
			}
		}
	}

	if cfg.Stats {
		printStats(scanned, excluded, processed, 0, totalSize, time.Since(start))
	}

	return nil
}

func outputPath(filename string, cfg *config.Config) string {
	ext := cfg.Suffixes.Encrypt

	if cfg.Decrypt {
		filename = strings.TrimSuffix(filename, cfg.Suffixes.Encrypt)
		ext = cfg.Suffixes.Decrypt
	}

	return filepath.Join(filepath.Dir(filename), filepath.Base(filename)+ext)
}

func printStats(scanned, excluded, processed, errored int, totalSize int64, duration time.Duration) {
	fmt.Fprintf(os.Stderr, "\nStats\n")
	fmt.Fprintf(os.Stderr, "  Scanned:   %d\n", scanned)
	fmt.Fprintf(os.Stderr, "  Excluded:  %d\n", excluded)
	fmt.Fprintf(os.Stderr, "  Processed: %d\n", processed)
	fmt.Fprintf(os.Stderr, "  Errors:    %d\n", errored)
	//nolint:gosec // totalSize is always non-negative (sum of file sizes)
	fmt.Fprintf(os.Stderr, "  Size:      %s\n", humanize.IBytes(uint64(max(0, totalSize))))
	fmt.Fprintf(os.Stderr, "  Duration:  %s\n", duration.Round(time.Millisecond))
}
