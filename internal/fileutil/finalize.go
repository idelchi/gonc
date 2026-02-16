// Package fileutil provides shared file operation helpers.
package fileutil

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TempContext holds state for an atomic file write operation.
type TempContext struct {
	SrcInfo os.FileInfo
	IsExec  bool
	TmpFile *os.File
	TmpName string
}

// NewTempContext stats the source file and creates a temp file for atomic writing.
// Caller must defer CleanupOnError.
func NewTempContext(filename, outPath string) (*TempContext, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("getting file info for %q: %w", filename, err)
	}

	const executableBits = 0o111

	tmpFile, err := os.CreateTemp(filepath.Dir(outPath), ".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("creating temporary file: %w", err)
	}

	return &TempContext{
		SrcInfo: info,
		IsExec:  info.Mode()&executableBits != 0,
		TmpFile: tmpFile,
		TmpName: tmpFile.Name(),
	}, nil
}

// CleanupOnError closes the temp file and removes it if the write failed.
func (tc *TempContext) CleanupOnError(errp *error) {
	tc.TmpFile.Close() //nolint:gosec // best-effort cleanup

	if *errp != nil {
		os.Remove(tc.TmpName) //nolint:gosec // best-effort cleanup
	}
}

// FinalizeOutput optionally preserves timestamps and returns the output file size.
func FinalizeOutput(outPath string, preserveTimestamps bool, modTime time.Time) (int64, error) {
	if preserveTimestamps {
		if err := os.Chtimes(outPath, modTime, modTime); err != nil {
			return 0, fmt.Errorf("preserving timestamps: %w", err)
		}
	}

	outInfo, err := os.Stat(outPath)
	if err != nil {
		return 0, fmt.Errorf("stat output %q: %w", outPath, err)
	}

	return outInfo.Size(), nil
}
