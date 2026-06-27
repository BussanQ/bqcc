// Package storage holds the small filesystem helpers shared by the CLI and the
// application service layer: JSON read/write, local identity load/save, and
// loading a published identity's referenced objects into a resolver.
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
	return os.WriteFile(path, data, 0o600)
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
	return os.WriteFile(path, data, 0o600)
}

// StoreReferencedObjects loads a published identity's public memory manifest,
// its objects and (optionally) attached attestations from the directory next to
// identityFile into the resolver's object store, returning the stored CIDs.
func StoreReferencedObjects(resolver *p2p.Resolver, identityFile string, state types.SignedIdentityState, includeAttestations bool) []string {
	baseDir := filepath.Dir(identityFile)
	stored := []string{}
	if state.Document.PublicMemoryRoot != "" {
		manifestFile := filepath.Join(baseDir, state.Document.PublicMemoryRoot+".json")
		if data, err := os.ReadFile(manifestFile); err == nil {
			resolver.StoreObject(state.Document.PublicMemoryRoot, data)
			stored = append(stored, state.Document.PublicMemoryRoot)
			var manifest types.MemoryManifest
			if err := json.Unmarshal(data, &manifest); err == nil {
				for _, cid := range manifest.Items {
					memoryFile := filepath.Join(baseDir, cid+".json")
					if payload, err := os.ReadFile(memoryFile); err == nil {
						resolver.StoreObject(cid, payload)
						stored = append(stored, cid)
					}
				}
			}
		}
	}
	if includeAttestations {
		for _, cid := range state.Document.AttestationRefs {
			attFile := filepath.Join(baseDir, cid+".json")
			if data, err := os.ReadFile(attFile); err == nil {
				resolver.StoreObject(cid, data)
				stored = append(stored, cid)
			}
		}
	}
	return stored
}
