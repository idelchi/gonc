package pathmatch_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/idelchi/gonc/pkg/pathmatch"
)

// Case is a single test case from a YAML golden file.
type Case struct {
	Pattern     string `yaml:"pattern"`
	Path        string `yaml:"path"`
	Match       bool   `yaml:"match"`
	Description string `yaml:"description,omitempty"`
}

// Group is a named collection of test cases.
type Group struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Cases       []Case `yaml:"cases"`
}

func loadSpecs(t *testing.T) map[string][]Group {
	t.Helper()

	files, err := filepath.Glob("testdata/*.yml")
	if err != nil {
		t.Fatalf("globbing testdata: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("no testdata/*.yml files found")
	}

	specs := make(map[string][]Group)

	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // test helper reads known testdata files
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}

		var groups []Group
		if err := yaml.Unmarshal(data, &groups); err != nil {
			t.Fatalf("parsing %s: %v", f, err)
		}

		specs[filepath.Base(f)] = groups
	}

	return specs
}

// forEachCase iterates file→group→case from the golden specs and calls fn per case.
func forEachCase(t *testing.T, fn func(t *testing.T, tc Case)) {
	t.Helper()

	forEachGroup(t, func(t *testing.T, cases []Case) {
		t.Helper()

		for i, tc := range cases {
			desc := tc.Description
			if desc == "" {
				desc = fmt.Sprintf("case_%d", i)
			}

			t.Run(desc, func(t *testing.T) {
				t.Parallel()
				fn(t, tc)
			})
		}
	})
}

// forEachGroup iterates file→group from the golden specs and calls fn per group.
func forEachGroup(t *testing.T, fn func(t *testing.T, cases []Case)) {
	t.Helper()

	for file, groups := range loadSpecs(t) {
		t.Run(file, func(t *testing.T) {
			t.Parallel()

			for _, g := range groups {
				t.Run(g.Name, func(t *testing.T) {
					t.Parallel()
					fn(t, g.Cases)
				})
			}
		})
	}
}

// TestMatch runs all golden test cases against pathmatch.Match.
func TestMatch(t *testing.T) {
	t.Parallel()

	forEachCase(t, func(t *testing.T, tc Case) {
		t.Helper()

		got, err := pathmatch.Match(tc.Pattern, tc.Path)
		if err != nil {
			t.Fatalf("Match(%q, %q) error: %v", tc.Pattern, tc.Path, err)
		}

		if got != tc.Match {
			t.Errorf("Match(%q, %q) = %v, want %v", tc.Pattern, tc.Path, got, tc.Match)
		}
	})
}

// TestMatcher tests the pre-compiled Matcher API.
func TestMatcher(t *testing.T) {
	t.Parallel()

	forEachGroup(t, func(t *testing.T, cases []Case) {
		t.Helper()

		// Group cases by pattern for batch testing.
		byPattern := make(map[string][]Case)

		for _, tc := range cases {
			byPattern[tc.Pattern] = append(byPattern[tc.Pattern], tc)
		}

		for pattern, pCases := range byPattern {
			matcher, err := pathmatch.NewMatcher([]string{pattern})
			if err != nil {
				t.Fatalf("NewMatcher(%q) error: %v", pattern, err)
			}

			for _, tc := range pCases {
				got := matcher.MatchAny(tc.Path)
				if got != tc.Match {
					t.Errorf("Matcher(%q).MatchAny(%q) = %v, want %v",
						pattern, tc.Path, got, tc.Match)
				}
			}
		}
	})
}

// TestFindParity cross-checks our implementation against actual find -path behavior.
// Each test case is verified by materializing the path in a temp directory
// and running find with the pattern.
func TestFindParity(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("find"); err != nil {
		t.Skip("find not available")
	}

	forEachCase(t, func(t *testing.T, tc Case) {
		t.Helper()

		if tc.Path == "" {
			t.Skip("empty path cannot be materialized")
		}

		findResult := runFind(t, tc.Pattern, tc.Path)

		if findResult != tc.Match {
			t.Errorf(
				"find -path disagrees with spec: find=%v, spec=%v for pattern=%q path=%q",
				findResult, tc.Match, tc.Pattern, tc.Path,
			)
		}

		got, err := pathmatch.Match(tc.Pattern, tc.Path)
		if err != nil {
			t.Fatalf("Match(%q, %q) error: %v", tc.Pattern, tc.Path, err)
		}

		if got != findResult {
			t.Errorf("Match(%q, %q) = %v, but find says %v",
				tc.Pattern, tc.Path, got, findResult)
		}
	})
}

// runFind materializes a path in a temp dir and checks if find -path matches it.
func runFind(t *testing.T, pattern, path string) bool {
	t.Helper()

	tmpDir := t.TempDir()

	// Materialize the path: create parent dirs and touch the file.
	fullPath := filepath.Join(tmpDir, path)

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o750); err != nil {
		t.Fatalf("mkdir for %q: %v", path, err)
	}

	if err := os.WriteFile(fullPath, nil, 0o600); err != nil {
		t.Fatalf("touch %q: %v", path, err)
	}

	// Build the find pattern: prepend tmpDir/ to the pattern so find can match.
	// find uses -path which matches against the full path from the search root.
	findPattern := filepath.Join(tmpDir, pattern)

	// Run: find <tmpDir> -type f -path '<findPattern>'
	//nolint:gosec // test parity check with find
	cmd := exec.CommandContext(t.Context(), "find", tmpDir, "-type", "f", "-path", findPattern)

	out, err := cmd.Output()
	if err != nil {
		// find returns exit code 0 even with no matches; an error means something went wrong.
		var exitErr *exec.ExitError
		if ok := errors.As(err, &exitErr); ok {
			t.Logf("find stderr: %s", exitErr.Stderr)
		}

		return false
	}

	return strings.TrimSpace(string(out)) != ""
}
