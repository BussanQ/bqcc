package memory

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/pkg/types"
)

func NewObject(kind string, payload string, visibility types.Visibility, refs []string, metadata map[string]string) (types.MemoryObject, error) {
	now := time.Now().UTC()
	base := map[string]interface{}{
		"type":       kind,
		"createdAt":  now.Format(time.RFC3339Nano),
		"payload":    payload,
		"visibility": visibility,
		"references": refs,
		"metadata":   metadata,
	}
	encoded, err := icrypto.CanonicalJSON(base)
	if err != nil {
		return types.MemoryObject{}, err
	}
	contentHash := icrypto.HashBytes(encoded)
	cid := icrypto.HashString("memory:" + contentHash)
	return types.MemoryObject{CID: cid, Type: kind, CreatedAt: now, ContentHash: contentHash, Payload: payload, Visibility: visibility, References: refs, Metadata: metadata}, nil
}

// objectCanonicalHash hashes the canonical pre-image of a memory object (the
// same subset used to derive its CID). Public objects hash the plaintext
// payload; private objects hash the ciphertext envelope.
func objectCanonicalHash(obj types.MemoryObject) (string, error) {
	var base map[string]interface{}
	if obj.Encryption != nil {
		base = map[string]interface{}{
			"type":       obj.Type,
			"createdAt":  obj.CreatedAt.Format(time.RFC3339Nano),
			"ciphertext": obj.Ciphertext,
			"encryption": map[string]interface{}{"algorithm": obj.Encryption.Algorithm, "recipientKeyId": obj.Encryption.RecipientKeyID, "ephemeralPublicKey": obj.Encryption.EphemeralPublicKey, "cipherNonce": obj.Encryption.CipherNonce},
			"visibility": obj.Visibility,
			"references": obj.References,
			"metadata":   obj.Metadata,
		}
	} else {
		base = map[string]interface{}{
			"type":       obj.Type,
			"createdAt":  obj.CreatedAt.Format(time.RFC3339Nano),
			"payload":    obj.Payload,
			"visibility": obj.Visibility,
			"references": obj.References,
			"metadata":   obj.Metadata,
		}
	}
	encoded, err := icrypto.CanonicalJSON(base)
	if err != nil {
		return "", err
	}
	return icrypto.HashBytes(encoded), nil
}

// ObjectCID recomputes the content-addressed CID of a memory object. It is the
// single source of truth shared by the constructors and by integrity checks on
// fetched objects.
func ObjectCID(obj types.MemoryObject) (string, error) {
	inner, err := objectCanonicalHash(obj)
	if err != nil {
		return "", err
	}
	return icrypto.HashString("memory:" + inner), nil
}

func NewPrivateObject(kind string, payload string, recipientKeyID string, recipientPublicKey []byte, refs []string, metadata map[string]string) (types.MemoryObject, error) {
	now := time.Now().UTC()
	plaintextBase := map[string]interface{}{
		"type":       kind,
		"createdAt":  now.Format(time.RFC3339Nano),
		"payload":    payload,
		"visibility": types.VisibilityPrivate,
		"references": refs,
		"metadata":   metadata,
	}
	plaintext, err := icrypto.CanonicalJSON(plaintextBase)
	if err != nil {
		return types.MemoryObject{}, err
	}
	ciphertext, ephemeralPublicKey, nonce, err := icrypto.EncryptForRecipient(plaintext, recipientPublicKey)
	if err != nil {
		return types.MemoryObject{}, err
	}
	encryption := &types.MemoryEncryption{
		Algorithm:          "x25519-aes256-gcm",
		RecipientKeyID:     recipientKeyID,
		EphemeralPublicKey: icrypto.BytesString(ephemeralPublicKey),
		CipherNonce:        icrypto.BytesString(nonce),
	}
	obj := types.MemoryObject{Type: kind, CreatedAt: now, ContentHash: icrypto.HashBytes(plaintext), Ciphertext: icrypto.BytesString(ciphertext), Encryption: encryption, Visibility: types.VisibilityPrivate, References: refs, Metadata: metadata}
	inner, err := objectCanonicalHash(obj)
	if err != nil {
		return types.MemoryObject{}, err
	}
	obj.CID = icrypto.HashString("memory:" + inner)
	return obj, nil
}

func DecryptObject(obj types.MemoryObject, recipientPrivateKey []byte) (string, error) {
	if obj.Encryption == nil {
		return obj.Payload, nil
	}
	ciphertext, err := icrypto.ParseBytes(obj.Ciphertext)
	if err != nil {
		return "", err
	}
	ephemeralPublicKey, err := icrypto.ParseBytes(obj.Encryption.EphemeralPublicKey)
	if err != nil {
		return "", err
	}
	nonce, err := icrypto.ParseBytes(obj.Encryption.CipherNonce)
	if err != nil {
		return "", err
	}
	plaintext, err := icrypto.DecryptForRecipient(ciphertext, ephemeralPublicKey, nonce, recipientPrivateKey)
	if err != nil {
		return "", err
	}
	if payload, ok := extractCanonicalStringField(plaintext, "payload"); ok {
		return payload, nil
	}
	return string(plaintext), nil
}

func extractCanonicalStringField(plaintext []byte, field string) (string, bool) {
	var ordered []interface{}
	if err := json.Unmarshal(plaintext, &ordered); err != nil {
		return "", false
	}
	for idx := 0; idx+1 < len(ordered); idx += 2 {
		key, ok := ordered[idx].(string)
		if !ok {
			return "", false
		}
		if key != field {
			continue
		}
		value, ok := ordered[idx+1].(string)
		return value, ok
	}
	return "", false
}

// objectSignaturePayload builds the canonical pre-image signed/verified for a
// memory object. Shared by SignObject and VerifyObject so the two can never drift.
func objectSignaturePayload(obj types.MemoryObject) map[string]interface{} {
	payload := map[string]interface{}{
		"cid":         obj.CID,
		"type":        obj.Type,
		"createdAt":   obj.CreatedAt.Format(time.RFC3339Nano),
		"contentHash": obj.ContentHash,
		"payload":     obj.Payload,
		"ciphertext":  obj.Ciphertext,
		"visibility":  obj.Visibility,
		"references":  obj.References,
		"metadata":    obj.Metadata,
	}
	if obj.Encryption != nil {
		payload["encryption"] = map[string]interface{}{"algorithm": obj.Encryption.Algorithm, "recipientKeyId": obj.Encryption.RecipientKeyID, "ephemeralPublicKey": obj.Encryption.EphemeralPublicKey, "wrappedKey": obj.Encryption.WrappedKey, "wrappedKeyNonce": obj.Encryption.WrappedKeyNonce, "cipherNonce": obj.Encryption.CipherNonce}
	}
	return payload
}

func SignObject(obj *types.MemoryObject, priv ed25519.PrivateKey) error {
	encoded, err := icrypto.CanonicalJSON(objectSignaturePayload(*obj))
	if err != nil {
		return err
	}
	obj.Signature = icrypto.SignBytes(priv, encoded)
	return nil
}

func VerifyObject(obj types.MemoryObject, pub ed25519.PublicKey) bool {
	encoded, err := icrypto.CanonicalJSON(objectSignaturePayload(obj))
	if err != nil {
		return false
	}
	return icrypto.VerifyBytes(pub, encoded, obj.Signature)
}

func NewManifest(visibility types.Visibility, items []types.MemoryObject) (types.MemoryManifest, error) {
	now := time.Now().UTC()
	cids := make([]string, 0, len(items))
	for _, item := range items {
		if visibility != item.Visibility {
			return types.MemoryManifest{}, fmt.Errorf("manifest visibility mismatch")
		}
		cids = append(cids, item.CID)
	}
	manifest := types.MemoryManifest{Version: "1", CreatedAt: now, Visibility: visibility, Items: cids}
	rootHash, err := manifestCanonicalHash(manifest)
	if err != nil {
		return types.MemoryManifest{}, err
	}
	manifest.RootHash = rootHash
	manifest.CID = icrypto.HashString("manifest:" + rootHash)
	return manifest, nil
}

func manifestCanonicalHash(manifest types.MemoryManifest) (string, error) {
	base := map[string]interface{}{
		"version":    manifest.Version,
		"createdAt":  manifest.CreatedAt.Format(time.RFC3339Nano),
		"visibility": manifest.Visibility,
		"items":      manifest.Items,
	}
	encoded, err := icrypto.CanonicalJSON(base)
	if err != nil {
		return "", err
	}
	return icrypto.HashBytes(encoded), nil
}

// ManifestCID recomputes the content-addressed CID of a manifest. Shared by
// NewManifest and by integrity checks on fetched objects.
func ManifestCID(manifest types.MemoryManifest) (string, error) {
	rootHash, err := manifestCanonicalHash(manifest)
	if err != nil {
		return "", err
	}
	return icrypto.HashString("manifest:" + rootHash), nil
}

func manifestSignaturePayload(manifest types.MemoryManifest) map[string]interface{} {
	return map[string]interface{}{"version": manifest.Version, "cid": manifest.CID, "createdAt": manifest.CreatedAt.Format(time.RFC3339Nano), "visibility": manifest.Visibility, "items": manifest.Items, "rootHash": manifest.RootHash}
}

func SignManifest(manifest *types.MemoryManifest, priv ed25519.PrivateKey) error {
	encoded, err := icrypto.CanonicalJSON(manifestSignaturePayload(*manifest))
	if err != nil {
		return err
	}
	manifest.Signature = icrypto.SignBytes(priv, encoded)
	return nil
}

func VerifyManifest(manifest types.MemoryManifest, pub ed25519.PublicKey) bool {
	encoded, err := icrypto.CanonicalJSON(manifestSignaturePayload(manifest))
	if err != nil {
		return false
	}
	return icrypto.VerifyBytes(pub, encoded, manifest.Signature)
}
