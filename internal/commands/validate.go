package commands

import (
	"fmt"
	"os"

	"github.com/spf13/viper"

	"github.com/idelchi/godyl/pkg/pretty"
	"github.com/idelchi/gonc/internal/config"
)

// validate unmarshals the configuration and performs validation checks.
// If cfg.Show is true, prints the configuration and exits.
func validate(cfg *config.Config, validations ...any) error {
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("unmarshalling config: %w", err)
	}

	if cfg.Show {
		pretty.PrintJSONMasked(cfg)

		os.Exit(0) //nolint: forbidigo
	}

	for _, v := range validations {
		if err := config.Validate(v); err != nil {
			return fmt.Errorf("validating config: %w\nSee --help for more info on usage", err)
		}
	}

	return nil
}
