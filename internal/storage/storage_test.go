package storage_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/example/decentid/internal/app"
	"github.com/example/decentid/internal/storage"
	"github.com/example/decentid/pkg/types"
)

func TestCollectReferencedObjectsKeepsPrivateMemoryOutOfPublishSet(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.json")
	svc := app.NewService(identityPath)
	if _, err := svc.CreateIdentity("Alice", "", false); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	if _, err := svc.AddMemory("note", "one", types.VisibilityPublic); err != nil {
		t.Fatalf("add first public memory: %v", err)
	}
	if _, err := svc.AddMemory("note", "two", types.VisibilityPublic); err != nil {
		t.Fatalf("add second public memory: %v", err)
	}
	privateMemory, err := svc.AddMemory("note", "secret", types.VisibilityPrivate)
	if err != nil {
		t.Fatalf("add private memory: %v", err)
	}
	id, err := storage.LoadIdentity(identityPath)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	objects, err := storage.CollectReferencedObjects(identityPath, id.SignedState(), storage.CollectOptions{IncludePublic: true})
	if err != nil {
		t.Fatalf("collect public objects: %v", err)
	}
	if len(objects) != 3 {
		t.Fatalf("expected public manifest plus two objects, got %d", len(objects))
	}
	for _, object := range objects {
		if object.CID == privateMemory.ObjectCID || object.CID == privateMemory.ManifestCID {
			t.Fatalf("private object entered public publish set: %s", object.CID)
		}
	}
}

func TestCollectReferencedObjectsRejectsTamperedObject(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "identity.json")
	svc := app.NewService(identityPath)
	if _, err := svc.CreateIdentity("Alice", "", false); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	created, err := svc.AddMemory("note", "hello", types.VisibilityPublic)
	if err != nil {
		t.Fatalf("add memory: %v", err)
	}
	data, err := os.ReadFile(created.ObjectFile)
	if err != nil {
		t.Fatalf("read memory object: %v", err)
	}
	var object map[string]interface{}
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("decode memory object: %v", err)
	}
	object["payload"] = "tampered"
	if err := storage.WriteJSON(created.ObjectFile, object); err != nil {
		t.Fatalf("write tampered object: %v", err)
	}
	id, err := storage.LoadIdentity(identityPath)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if _, err := storage.CollectReferencedObjects(identityPath, id.SignedState(), storage.CollectOptions{IncludePublic: true}); err == nil {
		t.Fatalf("expected tampered object to be rejected")
	}
}

func TestWriteFileSafelyReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "value.json")
	if err := storage.WriteFileSafely(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("write old value: %v", err)
	}
	if err := storage.WriteFileSafely(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("replace value: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read value: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("unexpected replacement contents %q", data)
	}
}
