package logic

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/filter"
	"github.com/idelchi/gonc/pkg/pathmatch"
)

// RunCheck validates that every include/exclude pattern matches at least one file.
func RunCheck(cfg *config.Config) error {
	includes, excludes, err := loadPatterns(cfg)
	if err != nil {
		return err
	}

	if len(includes) == 0 && len(excludes) == 0 {
		return errors.New("no include or exclude patterns to check")
	}

	candidates, err := collectFiles(cfg.Files)
	if err != nil {
		return err
	}

	var failures int

	failures += checkPatterns("include", includes, candidates, cfg.Quiet)
	failures += checkPatterns("exclude", excludes, candidates, cfg.Quiet)

	if failures > 0 {
		return fmt.Errorf("%d pattern(s) matched no files", failures)
	}

	return nil
}

// loadPatterns merges CLI and file-based include/exclude patterns.
func loadPatterns(cfg *config.Config) (includes, excludes []string, err error) {
	includes = append(includes, cfg.Include...)
	excludes = append(excludes, cfg.Exclude...)

	if cfg.IncludeFrom != "" {
		patterns, err := filter.LoadPatterns(cfg.IncludeFrom)
		if err != nil {
			return nil, nil, fmt.Errorf("loading include patterns: %w", err)
		}

		includes = append(includes, patterns...)
	}

	if cfg.ExcludeFrom != "" {
		patterns, err := filter.LoadPatterns(cfg.ExcludeFrom)
		if err != nil {
			return nil, nil, fmt.Errorf("loading exclude patterns: %w", err)
		}

		excludes = append(excludes, patterns...)
	}

	// Normalize: strip leading "./" so patterns match cleaned paths.
	for i, p := range includes {
		includes[i] = strings.TrimPrefix(p, "./")
	}

	for i, p := range excludes {
		excludes[i] = strings.TrimPrefix(p, "./")
	}

	return includes, excludes, nil
}

// collectFiles walks all positional args and returns every file path found.
func collectFiles(args []string) ([]string, error) {
	var paths []string

	seen := make(map[string]struct{})

	for _, arg := range args {
		arg = filepath.Clean(arg)

		info, err := os.Stat(arg)
		if err != nil {
			return nil, fmt.Errorf("stat %q: %w", arg, err)
		}

		if !info.IsDir() {
			if _, ok := seen[arg]; !ok {
				seen[arg] = struct{}{}
				paths = append(paths, filepath.ToSlash(filepath.Clean(arg)))
			}

			continue
		}

		err = filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			clean := filepath.ToSlash(filepath.Clean(path))
			if _, ok := seen[clean]; !ok {
				seen[clean] = struct{}{}
				paths = append(paths, clean)
			}

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walking %q: %w", arg, err)
		}
	}

	return paths, nil
}

// checkPatterns tests each pattern individually against candidates.
// Returns the number of patterns that matched zero files.
func checkPatterns(kind string, patterns, candidates []string, quiet bool) int {
	var failures int

	for _, pattern := range patterns {
		matcher, err := pathmatch.NewMatcher([]string{pattern})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s — invalid pattern: %v\n", kind, pattern, err)

			failures++

			continue
		}

		var count int

		for _, path := range candidates {
			if matcher.MatchAny(path) {
				count++
			}
		}

		if count == 0 {
			fmt.Fprintf(os.Stderr, "%s: %s — 0 files (ERROR)\n", kind, pattern)

			failures++
		} else if !quiet {
			fmt.Fprintf(os.Stderr, "%s: %s — %d files\n", kind, pattern, count)
		}
	}

	return failures
}
