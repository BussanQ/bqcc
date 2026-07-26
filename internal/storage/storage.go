// Package storage provides safe local persistence, referenced-object
// verification, resolver loading, and versioned backup bundles.
package storage

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/example/decentid/internal/identity"
	"github.com/example/decentid/internal/p2p"
	"github.com/example/decentid/pkg/types"
)

// ReadJSON reads and unmarshals a JSON file into out.
func ReadJSON(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// WriteJSON writes value as indented JSON with owner-only permissions.
func WriteJSON(path string, value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileSafely(path, data, 0o600)
}

// WriteFileSafely writes through a temporary file. When replacing an existing
// file, it keeps a rollback copy until the new file is in place; this also works
// on Windows where rename does not replace an existing destination.
func WriteFileSafely(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(perm); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.Rename(tempPath, path)
	} else if err != nil {
		return err
	}

	backup, err := os.CreateTemp(dir, "."+filepath.Base(path)+".bak-*")
	if err != nil {
		return err
	}
	backupPath := backup.Name()
	if err := backup.Close(); err != nil {
		return err
	}
	if err := os.Remove(backupPath); err != nil {
		return err
	}
	if err := os.Rename(path, backupPath); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Rename(backupPath, path)
		return err
	}
	_ = os.Remove(backupPath)
	return nil
}

// LoadIdentity reads a local identity file and reconstructs the verified identity.
func LoadIdentity(path string) (*identity.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	local, err := identity.UnmarshalLocal(data)
	if err != nil {
		return nil, err
	}
	return identity.FromLocal(local)
}

// SaveIdentity serializes and writes a local identity file (owner-only).
func SaveIdentity(path string, id *identity.Identity) error {
	data, err := identity.MarshalLocal(id.ExportLocal())
	if err != nil {
		return err
	}
	return WriteFileSafely(path, data, 0o600)
}

// StoreReferencedObjects validates and loads a published identity's public
// memory objects and optional standalone attestations into the resolver.
func StoreReferencedObjects(resolver *p2p.Resolver, identityFile string, state types.SignedIdentityState, includeAttestations bool) ([]string, error) {
	objects, err := CollectReferencedObjects(identityFile, state, CollectOptions{
		IncludePublic:       true,
		IncludeAttestations: includeAttestations,
	})
	if err != nil {
		return nil, err
	}
	stored := make([]string, 0, len(objects))
	for _, object := range objects {
		resolver.StoreObject(object.CID, object.Data)
		stored = append(stored, object.CID)
	}
	return stored, nil
}
