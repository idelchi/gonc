package logic

import (
	"fmt"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/encryption"
)

// Run is the main logic of the application.
func Run(cfg *config.Config) error {
	proc, err := encryption.NewProcessor(cfg)
	if err != nil {
		return fmt.Errorf("creating processor: %w", err)
	}

	err = proc.ProcessFiles()
	if err != nil {
		return fmt.Errorf("processing files: %w", err)
	}

	return nil
}
