package encryption

// Result represents the outcome of processing a single file.
type Result struct {
	Input  string // Input file path
	Output string // Output file path
	Error  error  // Any error that occurred during processing
}
