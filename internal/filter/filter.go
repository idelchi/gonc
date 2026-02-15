// Package filter selects files based on include/exclude patterns using find -path semantics.
package filter

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/idelchi/gonc/pkg/pathmatch"
)

// Filter selects files based on include/exclude patterns using find -path semantics.
// Empty includes means "match all". Excludes always win.
type Filter struct {
	includes *pathmatch.Matcher
	excludes *pathmatch.Matcher
}

// NewFilter compiles include/exclude patterns into a reusable filter.
func NewFilter(includes, excludes []string) (*Filter, error) {
	inc, err := pathmatch.NewMatcher(includes)
	if err != nil {
		return nil, fmt.Errorf("compiling include patterns: %w", err)
	}

	exc, err := pathmatch.NewMatcher(excludes)
	if err != nil {
		return nil, fmt.Errorf("compiling exclude patterns: %w", err)
	}

	return &Filter{includes: inc, excludes: exc}, nil
}

// match returns true if the relative path should be included.
func (f *Filter) match(path string, hasIncludes bool) bool {
	included := !hasIncludes || f.includes.MatchAny(path)
	excluded := f.excludes.MatchAny(path)

	return included && !excluded
}

// normalizePatterns strips leading "./" from patterns so they match cleaned paths.
func normalizePatterns(patterns []string) []string {
	for i, p := range patterns {
		patterns[i] = strings.TrimPrefix(p, "./")
	}

	return patterns
}

// Resolve takes positional args (files/directories) and include/exclude patterns.
// Files are added directly (bypassing filtering). Directories are walked and filtered.
// hasIncludes indicates whether include filtering was requested (flag provided),
// regardless of whether the pattern list is empty.
// Returns matched files and total candidates scanned.
func Resolve(args, includes, excludes []string, hasIncludes bool) (files []string, scanned int, err error) {
	for _, arg := range args {
		if err := validatePath(arg); err != nil {
			return nil, 0, err
		}
	}

	includes = normalizePatterns(includes)
	excludes = normalizePatterns(excludes)

	flt, err := NewFilter(includes, excludes)
	if err != nil {
		return nil, 0, err
	}

	seen := make(map[string]struct{})

	for _, arg := range args {
		arg = filepath.Clean(arg)

		info, err := os.Stat(arg)
		if err != nil {
			return nil, 0, fmt.Errorf("stat %q: %w", arg, err)
		}

		if !info.IsDir() {
			// Explicit file: bypass filtering, add directly.
			scanned++

			if _, ok := seen[arg]; ok {
				continue
			}

			seen[arg] = struct{}{}
			files = append(files, arg)

			continue
		}

		// Directory: walk and filter.
		walked, total, err := walkDir(arg, flt, hasIncludes)
		if err != nil {
			return nil, 0, err
		}

		scanned += total

		for _, path := range walked {
			if _, ok := seen[path]; ok {
				continue
			}

			seen[path] = struct{}{}
			files = append(files, path)
		}
	}

	if len(files) == 0 {
		return nil, scanned, fmt.Errorf("no files matched the provided patterns: %v", args)
	}

	return files, scanned, nil
}

// walkDir walks root recursively, returning files that pass the filter.
// Paths are relative to cwd (e.g. "src/main.go" when root is ".").
func walkDir(root string, flt *Filter, hasIncludes bool) (files []string, total int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		total++

		// Use forward slashes for pattern matching consistency.
		clean := filepath.ToSlash(filepath.Clean(path))

		if !flt.match(clean, hasIncludes) {
			return nil
		}

		files = append(files, path)

		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("walking %q: %w", root, err)
	}

	return files, total, nil
}

// validatePath rejects paths that escape the current working directory.
func validatePath(path string) error {
	if filepath.IsAbs(path) {
		return fmt.Errorf("absolute paths are not allowed: %q", path)
	}

	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, "..") {
		return fmt.Errorf("paths must be within the current working directory: %q", path)
	}

	return nil
}
