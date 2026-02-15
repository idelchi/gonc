// Package pathmatch implements find -path matching semantics.
//
// It follows fnmatch(3) without FNM_PATHNAME:
//   - * matches any characters including /
//   - ? matches exactly one character including /
//   - [...] matches one character from the set including /
//   - \ escapes the next character
//
// This differs from Go's filepath.Match where * does not cross directory separators.
package pathmatch

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Match reports whether path matches the pattern using find -path semantics.
func Match(pattern, path string) (bool, error) {
	re, err := compile(pattern)
	if err != nil {
		return false, err
	}

	return re.MatchString(path), nil
}

// Matcher pre-compiles patterns for reuse across many paths.
type Matcher struct {
	patterns []*regexp.Regexp
}

// NewMatcher compiles the given patterns into a reusable matcher.
func NewMatcher(patterns []string) (*Matcher, error) {
	matcher := &Matcher{patterns: make([]*regexp.Regexp, len(patterns))}

	for idx, p := range patterns {
		re, err := compile(p)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", p, err)
		}

		matcher.patterns[idx] = re
	}

	return matcher, nil
}

// MatchAny reports whether path matches any of the compiled patterns.
func (m *Matcher) MatchAny(path string) bool {
	for _, re := range m.patterns {
		if re.MatchString(path) {
			return true
		}
	}

	return false
}

var cache sync.Map //nolint:gochecknoglobals // package-level cache is appropriate for compiled regexps

// compile converts a find -path glob pattern to a compiled regexp.
// Results are cached for repeated use.
func compile(pattern string) (*regexp.Regexp, error) {
	if v, ok := cache.Load(pattern); ok {
		cached, _ := v.(*regexp.Regexp) //nolint:errcheck // type is guaranteed by cache.Store below

		return cached, nil
	}

	re, err := toRegexp(pattern)
	if err != nil {
		return nil, err
	}

	compiled, err := regexp.Compile(re)
	if err != nil {
		return nil, fmt.Errorf("compiling pattern %q: %w", pattern, err)
	}

	cache.Store(pattern, compiled)

	return compiled, nil
}

// toRegexp converts a find -path glob pattern to a regex string.
func toRegexp(pattern string) (string, error) {
	var buf strings.Builder

	buf.WriteString("^")

	pos := 0
	for pos < len(pattern) {
		switch pattern[pos] {
		case '*':
			buf.WriteString(".*")

			pos++

		case '?':
			buf.WriteString(".")

			pos++

		case '[':
			end, err := findClosingBracket(pattern, pos)
			if err != nil {
				return "", err
			}

			class := pattern[pos : end+1]
			// Convert [!...] to [^...] for regex negation
			if len(class) > 2 && class[1] == '!' {
				class = "[^" + class[2:]
			}

			buf.WriteString(class)

			pos = end + 1

		case '\\':
			if pos+1 < len(pattern) {
				buf.WriteString(regexp.QuoteMeta(string(pattern[pos+1])))

				pos += 2
			} else {
				return "", fmt.Errorf("trailing backslash in pattern %q", pattern)
			}

		default:
			buf.WriteString(regexp.QuoteMeta(string(pattern[pos])))

			pos++
		}
	}

	buf.WriteString("$")

	return buf.String(), nil
}

// findClosingBracket finds the index of the closing ] for a character class starting at pos.
func findClosingBracket(pattern string, pos int) (int, error) {
	idx := pos + 1

	// Skip leading ! (negation)
	if idx < len(pattern) && pattern[idx] == '!' {
		idx++
	}

	// Skip leading ] (literal)
	if idx < len(pattern) && pattern[idx] == ']' {
		idx++
	}

	for idx < len(pattern) {
		if pattern[idx] == ']' {
			return idx, nil
		}

		idx++
	}

	return 0, fmt.Errorf("unclosed character class in pattern %q", pattern)
}
