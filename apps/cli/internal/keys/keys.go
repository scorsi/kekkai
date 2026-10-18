// Package keys implements `kekkai keygen` and `kekkai pubkey` (spec §4, ADR 0015, 0017):
// X25519 keys in standard base64, checked against docs/spec/vectors/keygen.json.
package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// Clamp clears bits 0, 1, 2 of byte 0 and bit 7 of byte 31, and sets bit 6 of byte 31.
func Clamp(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// Generate draws 32 random bytes and returns them clamped.
func Generate() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	Clamp(k)
	return k, nil
}

// Public returns X25519(k, 9); any 32 bytes are accepted, X25519 clamps internally.
func Public(private []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// Encode is the text form: standard base64 with padding, one line.
func Encode(k []byte) string {
	return base64.StdEncoding.EncodeToString(k)
}

// Decode parses the text form; surrounding whitespace is ignored, the length must be 32.
func Decode(text string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("not a base64 32-byte key")
	}
	return k, nil
}
