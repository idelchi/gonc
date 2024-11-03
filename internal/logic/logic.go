package logic

import (
	"fmt"

	"github.com/idelchi/gonc/internal/config"
	"github.com/idelchi/gonc/internal/encryption"
)

func Run(cfg *config.Config) error {
	proc, err := encryption.NewProcessor(cfg)
	if err != nil {
		return fmt.Errorf("creating processor: %w", err)
	}

	return proc.ProcessFiles()
}
