package identity

import (
	"crypto/ed25519"
	"testing"

	"github.com/example/decentid/internal/memory"
	"github.com/example/decentid/pkg/types"
)

func TestNewIdentityImmediatelyMatchesReplay(t *testing.T) {
	id, err := New("alice")
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	if err := VerifyState(id.SignedState()); err != nil {
		t.Fatalf("new identity should match replayed state: %v", err)
	}
}

func TestIdentityIDsAreUniqueAndStable(t *testing.T) {
	alice, err := New("alice")
	if err != nil {
		t.Fatalf("new alice identity: %v", err)
	}
	bob, err := New("bob")
	if err != nil {
		t.Fatalf("new bob identity: %v", err)
	}
	if alice.Document.ID == bob.Document.ID {
		t.Fatalf("expected unique identity ids")
	}

	originalID := alice.Document.ID
	if err := alice.UpdateProfile(types.Profile{DisplayName: "alice", Bio: "updated"}); err != nil {
		t.Fatalf("update profile: %v", err)
	}
	if alice.Document.ID != originalID {
		t.Fatalf("identity id changed after profile update")
	}

	obj, err := memory.NewObject("note", "hello memory", types.VisibilityPublic, nil, map[string]string{"source": "test"})
	if err != nil {
		t.Fatalf("new memory object: %v", err)
	}
	if err := memory.SignObject(&obj, mustRootPrivateKey(alice, t)); err != nil {
		t.Fatalf("sign memory object: %v", err)
	}
	manifest, err := memory.NewManifest(types.VisibilityPublic, []types.MemoryObject{obj})
	if err != nil {
		t.Fatalf("new manifest: %v", err)
	}
	if err := memory.SignManifest(&manifest, mustRootPrivateKey(alice, t)); err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	if err := alice.AddPublicMemoryRoot(manifest.CID); err != nil {
		t.Fatalf("add public memory root: %v", err)
	}
	if alice.Document.ID != originalID {
		t.Fatalf("identity id changed after memory update")
	}
	if err := VerifyState(alice.SignedState()); err != nil {
		t.Fatalf("verify signed state: %v", err)
	}
}

func mustRootPrivateKey(id *Identity, t *testing.T) ed25519.PrivateKey {
	t.Helper()
	priv, err := id.PreferredRootPrivateKey()
	if err != nil {
		t.Fatalf("preferred root private key: %v", err)
	}
	return priv
}
