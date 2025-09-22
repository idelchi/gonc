// Package encryption provides file encryption using deterministic AES-SIV or randomized AES-CTR with HMAC-SHA256.
// It streams large files, authenticates chunk framing, and maintains file metadata such as executable bits.
// Deterministic mode requires a 64-byte key (128 hex characters); randomized mode requires a 32-byte key (64 hex
// characters).
package encryption
