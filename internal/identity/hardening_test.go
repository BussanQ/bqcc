package identity

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/pkg/types"
)

// Fix 1: a self-consistent, validly-signed chain that claims a DID not derived
// from its root key must be rejected.
func TestForgedIdentityIDRejected(t *testing.T) {
	id, err := New("alice")
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	rootPriv, err := id.PreferredRootPrivateKey()
	if err != nil {
		t.Fatalf("root priv: %v", err)
	}
	forgedID := "did:p2p:0000000000000000000000000000000000000000000000000000000000000000"
	forged, err := NewEvent(types.EventCreateIdentity, forgedID, "", id.Document.RootKeyID, id.Events[0].Payload, rootPriv)
	if err != nil {
		t.Fatalf("new event: %v", err)
	}
	if _, err := ReplayState([]types.IdentityEvent{forged}); err == nil || !strings.Contains(err.Error(), "identity id does not match root key") {
		t.Fatalf("expected DID binding rejection, got %v", err)
	}
}

// Fix 2: a management event signed by an active device key (not the root key)
// must be rejected during replay.
func TestDeviceSignedManagementEventRejected(t *testing.T) {
	id, err := New("alice")
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	dev, err := id.AddDevice("laptop")
	if err != nil {
		t.Fatalf("add device: %v", err)
	}
	devicePriv, err := id.SigningPrivateKeyByID(dev.ID)
	if err != nil {
		t.Fatalf("device priv: %v", err)
	}

	for _, tc := range []struct {
		name string
		typ  types.EventType
	}{
		{"AddDeviceKey", types.EventAddDeviceKey},
		{"RotateRootKey", types.EventRotateRootKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]interface{}{"key": map[string]interface{}{"id": "x"}}
			forged, err := NewEvent(tc.typ, id.Document.ID, id.Document.LatestEventID, dev.ID, payload, devicePriv)
			if err != nil {
				t.Fatalf("new event: %v", err)
			}
			events := append(append([]types.IdentityEvent(nil), id.Events...), forged)
			if _, err := ReplayState(events); err == nil || !strings.Contains(err.Error(), "not signed by active root key") {
				t.Fatalf("expected root-signed rejection, got %v", err)
			}
		})
	}
}

// Fix 3: a backdated event must be rejected; an equal-timestamp event must
// still replay (guards against an accidental strict-greater check).
func TestNonMonotonicTimestampRejected(t *testing.T) {
	id, err := New("alice")
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	rootPriv, err := id.PreferredRootPrivateKey()
	if err != nil {
		t.Fatalf("root priv: %v", err)
	}
	create := id.Events[0]

	backdated := signedEventAt(t, types.EventUpdateProfile, id.Document.ID, create.ID, id.Document.RootKeyID,
		map[string]interface{}{"profile": profilePayload(types.Profile{DisplayName: "back"})},
		rootPriv, create.Timestamp.Add(-time.Second))
	if _, err := ReplayState([]types.IdentityEvent{create, backdated}); err == nil || !strings.Contains(err.Error(), "non-monotonic timestamp") {
		t.Fatalf("expected non-monotonic rejection, got %v", err)
	}

	sameTS := signedEventAt(t, types.EventUpdateProfile, id.Document.ID, create.ID, id.Document.RootKeyID,
		map[string]interface{}{"profile": profilePayload(types.Profile{DisplayName: "same"})},
		rootPriv, create.Timestamp)
	doc, err := ReplayState([]types.IdentityEvent{create, sameTS})
	if err != nil {
		t.Fatalf("equal-timestamp replay should succeed, got %v", err)
	}
	if doc.Profile.DisplayName != "same" {
		t.Fatalf("expected equal-timestamp profile update to apply, got %q", doc.Profile.DisplayName)
	}
}

// signedEventAt builds a validly-signed event with a caller-chosen timestamp
// (NewEvent always stamps time.Now, so a backdating test needs this helper).
func signedEventAt(t *testing.T, eventType types.EventType, identityID, prevEventID, signerKeyID string, payload map[string]interface{}, priv ed25519.PrivateKey, ts time.Time) types.IdentityEvent {
	t.Helper()
	base := map[string]interface{}{
		"type":        eventType,
		"identityId":  identityID,
		"prevEventId": prevEventID,
		"signerKeyId": signerKeyID,
		"timestamp":   ts.Format(time.RFC3339Nano),
		"payload":     payload,
	}
	encoded, err := icrypto.CanonicalJSON(base)
	if err != nil {
		t.Fatalf("canonical json: %v", err)
	}
	return types.IdentityEvent{
		ID:          icrypto.HashString("event:" + icrypto.HashBytes(encoded)),
		Type:        eventType,
		IdentityID:  identityID,
		PrevEventID: prevEventID,
		SignerKeyID: signerKeyID,
		Timestamp:   ts,
		Payload:     payload,
		Signature:   icrypto.SignBytes(priv, encoded),
	}
}
