package encryption

// CipherMode represents the encryption mode to be used (CBC or Deterministic).
type CipherMode byte

const (
	// ModeCBC represents Cipher Block Chaining mode.
	ModeCBC CipherMode = iota
	// ModeDeterministic represents deterministic encryption using Tink.
	ModeDeterministic
)
