package filter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tidwall/jsonc"
)

// LoadPatterns reads a JSONC file and returns the parsed glob patterns.
func LoadPatterns(path string) ([]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is from user-supplied config
	if err != nil {
		return nil, fmt.Errorf("reading patterns file %q: %w", path, err)
	}

	clean := jsonc.ToJSONInPlace(data)

	var patterns []string
	if err := json.Unmarshal(clean, &patterns); err != nil {
		return nil, fmt.Errorf("parsing patterns file %q: %w", path, err)
	}

	return patterns, nil
}
