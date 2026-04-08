package attestation

import (
	"testing"
	"time"

	icrypto "github.com/example/decentid/internal/crypto"
)

func TestAttestationSignAndVerify(t *testing.T) {
	pub, priv, err := icrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	att, err := New("did:p2p:issuer", "root-key", "did:p2p:subject", "known", map[string]interface{}{"value": "alice"}, time.Hour, "evidence-1")
	if err != nil {
		t.Fatalf("new attestation: %v", err)
	}
	if err := Sign(&att, priv); err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	if !Verify(att, pub) {
		t.Fatalf("expected attestation verification to succeed")
	}
}

func TestExpiredAttestationFailsVerification(t *testing.T) {
	pub, priv, err := icrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	att, err := New("did:p2p:issuer", "root-key", "did:p2p:subject", "known", map[string]interface{}{"value": "alice"}, -time.Minute, "")
	if err != nil {
		t.Fatalf("new attestation: %v", err)
	}
	if err := Sign(&att, priv); err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	if Verify(att, pub) {
		t.Fatalf("expected expired attestation verification to fail")
	}
}
