package p2p

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/example/decentid/internal/identity"
	"github.com/example/decentid/internal/memory"
	"github.com/example/decentid/pkg/types"
)

func TestResolverPublishesAndResolvesStateAndObjects(t *testing.T) {
	publisherID, err := identity.New("publisher")
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	obj, err := memory.NewObject("note", "hello p2p", types.VisibilityPublic, nil, nil)
	if err != nil {
		t.Fatalf("new object: %v", err)
	}
	if err := memory.SignObject(&obj, mustRootPrivateKey(publisherID, t)); err != nil {
		t.Fatalf("sign object: %v", err)
	}
	manifest, err := memory.NewManifest(types.VisibilityPublic, []types.MemoryObject{obj})
	if err != nil {
		t.Fatalf("new manifest: %v", err)
	}
	if err := memory.SignManifest(&manifest, mustRootPrivateKey(publisherID, t)); err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	if err := publisherID.AddPublicMemoryRoot(manifest.CID); err != nil {
		t.Fatalf("update memory root: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	publisher, err := NewResolver(ctx, "/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("new publisher resolver: %v", err)
	}
	defer publisher.Close()
	subscriber, err := NewResolver(ctx, "/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("new subscriber resolver: %v", err)
	}
	defer subscriber.Close()

	state := publisherID.SignedState()
	publisher.StoreObject(obj.CID, mustJSON(obj, t))
	publisher.StoreObject(manifest.CID, mustJSON(manifest, t))
	publisher.mu.Lock()
	publisher.states[publisherID.Document.ID] = state
	publisher.mu.Unlock()

	if err := subscriber.DialPeer(ctx, publisher.AddrStrings()[0]); err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	remoteState, err := subscriber.ResolveRemote(ctx, publisher.Host().ID(), publisherID.Document.ID)
	if err != nil {
		t.Fatalf("resolve remote: %v", err)
	}
	if remoteState.Document.ID != publisherID.Document.ID {
		t.Fatalf("unexpected resolved identity id")
	}
	if remoteState.Document.PublicMemoryRoot != manifest.CID {
		t.Fatalf("unexpected public memory root")
	}
	remoteManifestData, err := subscriber.ResolveObjectRemote(ctx, publisher.Host().ID(), manifest.CID)
	if err != nil {
		t.Fatalf("resolve manifest object: %v", err)
	}
	var remoteManifest types.MemoryManifest
	if err := json.Unmarshal(remoteManifestData, &remoteManifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if len(remoteManifest.Items) != 1 || remoteManifest.Items[0] != obj.CID {
		t.Fatalf("unexpected manifest items")
	}
	remoteObjectData, err := subscriber.ResolveObjectRemote(ctx, publisher.Host().ID(), obj.CID)
	if err != nil {
		t.Fatalf("resolve memory object: %v", err)
	}
	var remoteObject types.MemoryObject
	if err := json.Unmarshal(remoteObjectData, &remoteObject); err != nil {
		t.Fatalf("unmarshal object: %v", err)
	}
	if remoteObject.Payload != "hello p2p" {
		t.Fatalf("unexpected memory payload")
	}
}

func mustJSON(value interface{}, t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return data
}

func mustRootPrivateKey(id *identity.Identity, t *testing.T) []byte {
	t.Helper()
	priv, err := id.PreferredRootPrivateKey()
	if err != nil {
		t.Fatalf("preferred root private key: %v", err)
	}
	return priv
}
