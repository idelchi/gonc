package encryption

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	aes_sivpb "github.com/tink-crypto/tink-go/v2/proto/aes_siv_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"

	"google.golang.org/protobuf/proto"
)

// encryptDeterministic encrypts the input file using deterministic encryption.
// It streams data through a deterministic AEAD writer for memory efficiency.
func (p *Processor) encryptDeterministic(r io.Reader, w io.Writer) error {
	sw := newStreamingWriter(w, p.daead, nil)
	defer sw.Close()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, err := sw.Write(buf[:n]); err != nil {
				return fmt.Errorf("writing to stream: %w", err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}
	}

	return nil
}

// decryptDeterministic decrypts the input file using deterministic encryption.
// It reads and processes encrypted chunks sequentially.
func (p *Processor) decryptDeterministic(r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)

	for {
		// Read chunk size
		var chunkSize uint32
		if err := binary.Read(br, binary.BigEndian, &chunkSize); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("reading chunk size: %w", err)
		}

		// Read encrypted chunk
		encrypted := make([]byte, chunkSize)
		if _, err := io.ReadFull(br, encrypted); err != nil {
			return fmt.Errorf("reading encrypted chunk: %w", err)
		}

		// Decrypt chunk
		decrypted, err := p.daead.DecryptDeterministically(encrypted, nil)
		if err != nil {
			return fmt.Errorf("decrypting chunk: %w", err)
		}

		// Write decrypted chunk
		if _, err := w.Write(decrypted); err != nil {
			return fmt.Errorf("writing decrypted chunk: %w", err)
		}
	}

	return nil
}

// newDeterministicAEADKeyHandle creates a Tink keyset handle for AES-SIV from raw key bytes.
// The handle is used to initialize the deterministic AEAD primitive.
func newDeterministicAEADKeyHandle(key []byte) (*keyset.Handle, error) {
	// Create an AesSivKey proto message
	aesSivKey := &aes_sivpb.AesSivKey{
		Version:  0,
		KeyValue: key,
	}

	serializedKey, err := proto.Marshal(aesSivKey)
	if err != nil {
		return nil, fmt.Errorf("serializing AesSivKey: %w", err)
	}

	keyData := &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}

	// Create a Keyset containing the key
	ks := &tinkpb.Keyset{
		PrimaryKeyId: 1,
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData:          keyData,
				Status:           tinkpb.KeyStatusType_ENABLED,
				KeyId:            1,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	// Serialize the Keyset
	serializedKeyset, err := proto.Marshal(ks)
	if err != nil {
		return nil, fmt.Errorf("serializing keyset: %w", err)
	}

	// Use insecurecleartextkeyset.Read with keyset.NewBinaryReader
	kh, err := insecurecleartextkeyset.Read(
		keyset.NewBinaryReader(bytes.NewReader(serializedKeyset)))
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle: %w", err)
	}

	return kh, nil
}
