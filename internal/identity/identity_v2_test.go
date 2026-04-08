package identity

import (
	"testing"
	"time"

	"github.com/example/decentid/internal/attestation"
)

func TestRotateRootKeepsIdentityStableAndReplayValid(t *testing.T) {
	id, err := New("alice")
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	originalID := id.Document.ID
	oldRootKeyID := id.Document.RootKeyID
	rotated, err := id.RotateRoot("rotated")
	if err != nil {
		t.Fatalf("rotate root: %v", err)
	}
	if id.Document.ID != originalID {
		t.Fatalf("identity id changed after root rotation")
	}
	if id.Document.RootKeyID != rotated.ID {
		t.Fatalf("document root key not updated")
	}
	if oldRootKeyID == id.Document.RootKeyID {
		t.Fatalf("expected new root key id")
	}
	if err := VerifyState(id.SignedState()); err != nil {
		t.Fatalf("verify signed state after root rotation: %v", err)
	}
}

func TestAttachAttestationRefUpdatesDocument(t *testing.T) {
	issuer, err := New("issuer")
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	subject, err := New("subject")
	if err != nil {
		t.Fatalf("new subject: %v", err)
	}
	att, err := attestation.New(issuer.Document.ID, issuer.Document.RootKeyID, subject.Document.ID, "known", map[string]interface{}{"value": "subject"}, time.Hour, "evidence")
	if err != nil {
		t.Fatalf("new attestation: %v", err)
	}
	if err := attestation.Sign(&att, mustRootPrivateKey(issuer, t)); err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	if err := subject.AttachAttestationRef(att.CID); err != nil {
		t.Fatalf("attach attestation ref: %v", err)
	}
	if len(subject.Document.AttestationRefs) != 1 || subject.Document.AttestationRefs[0] != att.CID {
		t.Fatalf("unexpected attestation refs")
	}
	if err := VerifyState(subject.SignedState()); err != nil {
		t.Fatalf("verify subject state: %v", err)
	}
}
