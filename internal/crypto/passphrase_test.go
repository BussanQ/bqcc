package crypto

import (
	"bytes"
	"testing"
)

func TestPassphraseRoundTrip(t *testing.T) {
	plaintext := []byte(`{"document":{"id":"did:p2p:abc"},"localKeys":[]}`)
	blob, err := EncryptWithPassphrase(plaintext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatalf("ciphertext leaks plaintext")
	}
	out, err := DecryptWithPassphrase(blob, "correct horse battery staple")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestPassphraseWrongKeyFails(t *testing.T) {
	blob, err := EncryptWithPassphrase([]byte("secret"), "right")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptWithPassphrase(blob, "wrong"); err == nil {
		t.Fatalf("expected decryption with wrong passphrase to fail")
	}
}

func TestPassphraseTamperFails(t *testing.T) {
	blob, err := EncryptWithPassphrase([]byte("secret"), "pw")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob[len(blob)-1] ^= 0xff
	if _, err := DecryptWithPassphrase(blob, "pw"); err == nil {
		t.Fatalf("expected tampered blob to fail authentication")
	}
}
