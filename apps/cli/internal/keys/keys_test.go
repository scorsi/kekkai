package keys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The shared vectors (ADR 0015, 0020), the same file kekkai-core's suite reproduces.
const vectors = "../../../../docs/spec/vectors/keygen.json"

type vectorFile struct {
	Keys []struct {
		Name              string `json:"name"`
		PrivateKey        string `json:"private_key"`
		PrivateKeyClamped string `json:"private_key_clamped"`
		PublicKey         string `json:"public_key"`
		PrivateKeyBase64  string `json:"private_key_base64"`
		PublicKeyBase64   string `json:"public_key_base64"`
	} `json:"keys"`
	Clamping struct {
		RandomBytes             string `json:"random_bytes"`
		PrivateKey              string `json:"private_key"`
		PublicKey               string `json:"public_key"`
		PublicKeyOfUnclampedInp string `json:"public_key_of_unclamped_input"`
	} `json:"clamping"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func public(t *testing.T, k []byte) []byte {
	t.Helper()
	p, err := Public(k)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile(vectors)
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Keys) == 0 {
		t.Fatal("no keys in the vector file")
	}
	for _, k := range v.Keys {
		priv, clamped, pub := unhex(t, k.PrivateKey), unhex(t, k.PrivateKeyClamped), unhex(t, k.PublicKey)
		c := bytes.Clone(priv)
		Clamp(c)
		if !bytes.Equal(c, clamped) {
			t.Errorf("%s: clamp", k.Name)
		}
		if !bytes.Equal(public(t, priv), pub) || !bytes.Equal(public(t, clamped), pub) {
			t.Errorf("%s: public key", k.Name)
		}
		if Encode(priv) != k.PrivateKeyBase64 || Encode(pub) != k.PublicKeyBase64 {
			t.Errorf("%s: base64", k.Name)
		}
		if d, err := Decode(k.PrivateKeyBase64 + "\n"); err != nil || !bytes.Equal(d, priv) {
			t.Errorf("%s: decode", k.Name)
		}
	}
	c := v.Clamping
	r := unhex(t, c.RandomBytes)
	if !bytes.Equal(public(t, r), unhex(t, c.PublicKeyOfUnclampedInp)) {
		t.Error("clamping: public key of the unclamped input")
	}
	Clamp(r)
	if !bytes.Equal(r, unhex(t, c.PrivateKey)) || !bytes.Equal(public(t, r), unhex(t, c.PublicKey)) {
		t.Error("clamping: clamped key")
	}
}

func TestGenerateIsClamped(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	c := bytes.Clone(k)
	Clamp(c)
	if !bytes.Equal(c, k) {
		t.Error("generated key is not clamped")
	}
	if _, err := Decode("AAAA"); err == nil {
		t.Error("short key accepted")
	}
}
