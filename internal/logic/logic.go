// Package logic implements the core business logic for the encryption/decryption.
package logic

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/dustin/go-humanize"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/encryption"
	"github.com/idelchi/gonc/internal/fileutil"
	"github.com/idelchi/gonc/internal/filter"
)

// Run is the main logic of the application.
func Run(cfg *config.Config) error {
	scanned, excluded, start, done, err := preamble(cfg)
	if done || err != nil {
		return err
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

// preamble resolves files and handles dry run. Returns done=true if dry run was executed.
func preamble(cfg *config.Config) (int, int, time.Time, bool, error) {
	start := time.Now()

	scanned, err := resolveFiles(cfg)
	if err != nil {
		return 0, 0, start, false, fmt.Errorf("resolving files: %w", err)
	}

	excluded := scanned - len(cfg.Files)

	if cfg.Dry {
		return scanned, excluded, start, true, dryRun(cfg, scanned, excluded, start)
	}

	return scanned, excluded, start, false, nil
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
//
//nolint:unparam // signature kept for consistency with Run callers
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

// RunRedact replaces file contents with a fixed string, writing output to <file><encrypt-ext>.
//
//nolint:cyclop,gocognit // parallel processing pipeline with printer goroutine
func RunRedact(cfg *config.Config) error {
	scanned, excluded, start, done, err := preamble(cfg)
	if done || err != nil {
		return err
	}

	type result struct {
		input      string
		output     string
		outputSize int64
		err        error
	}

	results := make(chan result, len(cfg.Files))

	group := errgroup.Group{}
	group.SetLimit(cfg.Parallel)

	printed := make(chan struct{})

	var processed, errored int

	var totalSize int64

	go func() {
		defer close(printed)

		for res := range results {
			if res.err != nil {
				errored++

				fmt.Fprintf(os.Stderr, "Error processing %q: %v\n", res.input, res.err)
			} else {
				processed++

				totalSize += res.outputSize

				if !cfg.Quiet {
					fmt.Printf("Processed %q -> %q\n", res.input, res.output) //nolint:forbidigo
				}
			}

			if cfg.Delete && res.err == nil {
				if err := os.Remove(res.input); err != nil {
					fmt.Fprintf(os.Stderr, "Error deleting %q: %v\n", res.input, err)
				} else if !cfg.Quiet {
					fmt.Printf("Deleted %q\n", res.input) //nolint:forbidigo
				}
			}
		}
	}()

	for _, file := range cfg.Files {
		group.Go(func() error {
			outPath := outputPath(file, cfg)

			size, err := redactFile(file, outPath, cfg)
			if err != nil {
				results <- result{input: file, err: err}

				return err
			}

			results <- result{input: file, output: outPath, outputSize: size}

			return nil
		})
	}

	err = group.Wait()

	close(results)

	<-printed

	if cfg.Stats {
		printStats(scanned, excluded, processed, errored, totalSize, time.Since(start))
	}

	if err != nil {
		return fmt.Errorf("redacting files: %w", err)
	}

	return nil
}

// redactFile writes the content string to a temp file and atomically renames it to outPath.
func redactFile(filename, outPath string, cfg *config.Config) (size int64, err error) {
	tc, err := fileutil.NewTempContext(filename, outPath)
	if err != nil {
		return 0, fmt.Errorf("preparing atomic write: %w", err)
	}

	defer tc.CleanupOnError(&err)

	if _, err = tc.TmpFile.WriteString(cfg.Content); err != nil {
		return 0, fmt.Errorf("writing content: %w", err)
	}

	const ownerReadWrite = 0o600

	perm := os.FileMode(ownerReadWrite)

	if tc.IsExec {
		perm |= 0o111
	}

	if err := os.Chmod(tc.TmpName, perm); err != nil {
		return 0, fmt.Errorf("setting file permissions: %w", err)
	}

	if err := tc.TmpFile.Close(); err != nil {
		return 0, fmt.Errorf("closing temporary file: %w", err)
	}

	if err := os.Rename(tc.TmpName, outPath); err != nil {
		return 0, fmt.Errorf("renaming output file: %w", err)
	}

	size, err = fileutil.FinalizeOutput(outPath, cfg.PreserveTimestamps, tc.SrcInfo.ModTime())
	if err != nil {
		return 0, fmt.Errorf("finalizing output: %w", err)
	}

	return size, nil
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
