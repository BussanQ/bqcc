package memory

import (
	"strings"
	"testing"

	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/pkg/types"
)

func TestPrivateObjectEncryptsAndDecryptsPayload(t *testing.T) {
	pub, priv, err := icrypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate x25519 keypair: %v", err)
	}
	obj, err := NewPrivateObject("note", "secret hello", "enc-key", pub, nil, map[string]string{"source": "test"})
	if err != nil {
		t.Fatalf("new private object: %v", err)
	}
	if obj.Payload != "" {
		t.Fatalf("expected private object payload to stay empty")
	}
	if obj.Visibility != types.VisibilityPrivate {
		t.Fatalf("expected private visibility")
	}
	if obj.Encryption == nil || obj.Ciphertext == "" {
		t.Fatalf("expected ciphertext and encryption metadata")
	}
	decrypted, err := DecryptObject(obj, priv)
	if err != nil {
		t.Fatalf("decrypt object: %v", err)
	}
	if decrypted != "secret hello" {
		t.Fatalf("unexpected decrypted payload: %q", decrypted)
	}
}

func TestPrivateObjectDoesNotExposePlaintext(t *testing.T) {
	pub, _, err := icrypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate x25519 keypair: %v", err)
	}
	obj, err := NewPrivateObject("note", "top-secret-payload", "enc-key", pub, nil, nil)
	if err != nil {
		t.Fatalf("new private object: %v", err)
	}
	if strings.Contains(obj.Ciphertext, "top-secret-payload") {
		t.Fatalf("ciphertext leaked plaintext")
	}
}
