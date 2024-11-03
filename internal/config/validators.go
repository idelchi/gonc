package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/idelchi/gogen/pkg/validator"
)

// registerExclusive adds a custom validator ensuring two fields are mutually exclusive.
// It registers both the validation logic and a human-readable error message.
func registerExclusive(v *validator.Validator) error {
	// Register the exclusive validation
	if err := v.RegisterValidationAndTranslation(
		"exclusive",
		validateExclusive,
		"{0} is mutually exclusive",
	); err != nil {
		return fmt.Errorf("registering exclusive validation: %w", err)
	}

	v.Validator().RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("label"), ",", 2)[0]
		if name == "-" {
			return fld.Name
		}
		if name != "" {
			return name
		}
		return fld.Name
	})

	return nil
}

// validateExclusive checks if two fields are mutually exclusive.
// Returns false if both fields have non-empty values.
func validateExclusive(fl validator.FieldLevel) bool {
	otherFieldName := fl.Param()
	field := fl.Field()
	otherField := fl.Parent().FieldByName(otherFieldName)

	if !field.IsValid() || !otherField.IsValid() {
		return true
	}

	if field.Kind() == reflect.String && otherField.Kind() == reflect.String {
		currentValue := field.String()
		otherValue := otherField.String()
		return !(currentValue != "" && otherValue != "")
	}

	return true
}
