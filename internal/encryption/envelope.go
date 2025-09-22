package encryption

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	envelopeMagic   = "GONC"
	envelopeVersion = byte(1)
	envelopeTagSize = sha256.Size

	envelopeFlagExec = 0x01
)

type envelopeMode byte

const (
	modeDeterministic envelopeMode = 0x01
	modeRandomized    envelopeMode = 0x02
)

const envelopeHeaderSize = len(envelopeMagic) + 3

// ErrProcessing indicates an error during envelope processing.
var ErrProcessing = errors.New("envelope processing error")

func newEnvelopeHeader(mode envelopeMode, executable bool) []byte {
	header := make([]byte, envelopeHeaderSize)
	copy(header, []byte(envelopeMagic))

	header[len(envelopeMagic)] = envelopeVersion

	var flags byte

	if executable {
		flags |= envelopeFlagExec
	}

	header[len(envelopeMagic)+1] = flags
	header[len(envelopeMagic)+2] = byte(mode)

	return header
}

func parseEnvelopeHeader(header []byte) (envelopeMode, bool, error) {
	if len(header) != envelopeHeaderSize {
		return 0, false, fmt.Errorf("%w: envelope header too short", ErrProcessing)
	}

	if !bytes.Equal(header[:len(envelopeMagic)], []byte(envelopeMagic)) {
		return 0, false, fmt.Errorf("%w: invalid envelope magic", ErrProcessing)
	}

	version := header[len(envelopeMagic)]
	if version != envelopeVersion {
		return 0, false, fmt.Errorf("%w: unsupported envelope version %d", ErrProcessing, version)
	}

	flags := header[len(envelopeMagic)+1]
	mode := envelopeMode(header[len(envelopeMagic)+2])

	switch mode {
	case modeDeterministic, modeRandomized:
	default:
		return 0, false, fmt.Errorf("%w: unsupported envelope mode %d", ErrProcessing, mode)
	}

	executable := flags&envelopeFlagExec != 0

	return mode, executable, nil
}

func deriveRandomizedKeys(key []byte) ([]byte, []byte, error) {
	const (
		hkdfOutputLen       = 64
		randomizedEncKeyLen = 32
		randomizedMacKeyLen = 32
	)

	hkdfReader := hkdf.New(sha256.New, key, nil, []byte("gonc/randomized"))
	derived := make([]byte, hkdfOutputLen)

	if _, err := io.ReadFull(hkdfReader, derived); err != nil {
		return nil, nil, fmt.Errorf("deriving randomized keys: %w", err)
	}

	return derived[:randomizedEncKeyLen], derived[randomizedEncKeyLen:], nil
}
