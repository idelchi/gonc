package encryption

// Result represents the outcome of processing a single file.
type Result struct {
	// Input file path
	Input string

	// Output file path
	Output string

	// Any error that occurred during processing
	Error error
}
