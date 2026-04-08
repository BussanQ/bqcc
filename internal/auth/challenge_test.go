package auth

import (
	"testing"
	"time"

	"github.com/example/decentid/internal/identity"
)

func TestChallengeResponseVerification(t *testing.T) {
	id, err := identity.New("alice")
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	challenge, err := NewChallenge(id.Document.ID, time.Minute)
	if err != nil {
		t.Fatalf("new challenge: %v", err)
	}
	response, err := SignChallenge(challenge, id.DeviceKeyID(), id)
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	if !VerifyChallenge(response, id.Document) {
		t.Fatalf("expected challenge verification to succeed")
	}
}

func TestSignChallengeRejectsRevokedDevice(t *testing.T) {
	id, err := identity.New("alice")
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	device, err := id.AddDevice("phone")
	if err != nil {
		t.Fatalf("add device: %v", err)
	}
	challenge, err := NewChallenge(id.Document.ID, time.Minute)
	if err != nil {
		t.Fatalf("new challenge: %v", err)
	}
	if _, err := SignChallenge(challenge, device.ID, id); err != nil {
		t.Fatalf("sign challenge before revoke: %v", err)
	}
	if err := id.RevokeDevice(device.ID, "lost"); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	if _, err := SignChallenge(challenge, device.ID, id); err == nil {
		t.Fatalf("expected revoked device signing to fail")
	}
}
