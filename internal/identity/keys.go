package identity

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/pkg/types"
)

type LocalKeyRecord struct {
	KeyID      string        `json:"keyId"`
	Type       string        `json:"type"`
	Role       types.KeyRole `json:"role"`
	PrivateKey string        `json:"privateKey"`
	Label      string        `json:"label,omitempty"`
}

type LocalIdentity struct {
	Document                 types.IdentityDocument `json:"document"`
	Events                   []types.IdentityEvent  `json:"events"`
	LocalKeys                []LocalKeyRecord       `json:"localKeys"`
	PreferredRootKeyID       string                 `json:"preferredRootKeyId,omitempty"`
	PreferredDeviceKeyID     string                 `json:"preferredDeviceKeyId,omitempty"`
	PreferredEncryptionKeyID string                 `json:"preferredEncryptionKeyId,omitempty"`
}

func (i *Identity) SignedState() types.SignedIdentityState {
	return types.SignedIdentityState{
		Document: i.Document,
		Events:   append([]types.IdentityEvent(nil), i.Events...),
	}
}

func (i *Identity) ExportLocal() LocalIdentity {
	localKeys := make([]LocalKeyRecord, 0, len(i.LocalKeys))
	for _, key := range i.LocalKeys {
		localKeys = append(localKeys, LocalKeyRecord{
			KeyID:      key.KeyID,
			Type:       key.Type,
			Role:       key.Role,
			PrivateKey: icrypto.BytesString(key.PrivateKey),
			Label:      key.Label,
		})
	}
	return LocalIdentity{
		Document:                 i.Document,
		Events:                   append([]types.IdentityEvent(nil), i.Events...),
		LocalKeys:                localKeys,
		PreferredRootKeyID:       i.PreferredRootKeyID,
		PreferredDeviceKeyID:     i.PreferredDeviceKeyID,
		PreferredEncryptionKeyID: i.PreferredEncryptionKeyID,
	}
}

func FromLocal(local LocalIdentity) (*Identity, error) {
	keys := make([]PrivateKeyRecord, 0, len(local.LocalKeys))
	for _, localKey := range local.LocalKeys {
		priv, err := icrypto.ParseBytes(localKey.PrivateKey)
		if err != nil {
			return nil, err
		}
		keys = append(keys, PrivateKeyRecord{
			KeyID:      localKey.KeyID,
			Type:       localKey.Type,
			Role:       localKey.Role,
			PrivateKey: priv,
			Label:      localKey.Label,
		})
	}
	identity := &Identity{
		Document:                 local.Document,
		Events:                   append([]types.IdentityEvent(nil), local.Events...),
		LocalKeys:                keys,
		PreferredRootKeyID:       local.PreferredRootKeyID,
		PreferredDeviceKeyID:     local.PreferredDeviceKeyID,
		PreferredEncryptionKeyID: local.PreferredEncryptionKeyID,
	}
	if err := VerifyState(identity.SignedState()); err != nil {
		return nil, err
	}
	return identity, nil
}

func MarshalLocal(local LocalIdentity) ([]byte, error) {
	return json.MarshalIndent(local, "", "  ")
}

func UnmarshalLocal(data []byte) (LocalIdentity, error) {
	var local LocalIdentity
	if err := json.Unmarshal(data, &local); err != nil {
		return local, err
	}
	for idx := range local.Events {
		normalizeEventPayload(&local.Events[idx])
	}
	return local, nil
}

func UnmarshalSignedState(data []byte) (types.SignedIdentityState, error) {
	var state types.SignedIdentityState
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	for idx := range state.Events {
		normalizeEventPayload(&state.Events[idx])
	}
	return state, nil
}

func normalizeEventPayload(event *types.IdentityEvent) {
	if event == nil || event.Payload == nil {
		return
	}
	profile, ok := event.Payload["profile"].(map[string]interface{})
	if !ok {
		return
	}
	attributes, ok := profile["attributes"].(map[string]interface{})
	if !ok {
		return
	}
	normalized := make(map[string]string, len(attributes))
	for key, value := range attributes {
		if str, ok := value.(string); ok {
			normalized[key] = str
		}
	}
	profile["attributes"] = normalized
}

func (i *Identity) PreferredRootPrivateKey() (ed25519.PrivateKey, error) {
	if i.PreferredRootKeyID == "" {
		return nil, fmt.Errorf("preferred root key not set")
	}
	return i.SigningPrivateKeyByID(i.PreferredRootKeyID)
}

func (i *Identity) PreferredDevicePrivateKey() (ed25519.PrivateKey, error) {
	if i.PreferredDeviceKeyID == "" {
		return nil, fmt.Errorf("preferred device key not set")
	}
	return i.SigningPrivateKeyByID(i.PreferredDeviceKeyID)
}

func (i *Identity) PreferredEncryptionPrivateKey() ([]byte, error) {
	if i.PreferredEncryptionKeyID == "" {
		return nil, fmt.Errorf("preferred encryption key not set")
	}
	return i.PrivateKeyByID(i.PreferredEncryptionKeyID)
}

func (i *Identity) SigningPrivateKeyByID(keyID string) (ed25519.PrivateKey, error) {
	for _, key := range i.LocalKeys {
		if key.KeyID == keyID {
			if key.Type != "ed25519" {
				return nil, fmt.Errorf("key %s is not an ed25519 signing key", keyID)
			}
			if len(key.PrivateKey) != ed25519.PrivateKeySize {
				return nil, fmt.Errorf("invalid ed25519 private key length for %s", keyID)
			}
			return ed25519.PrivateKey(key.PrivateKey), nil
		}
	}
	return nil, fmt.Errorf("private key not found: %s", keyID)
}

func (i *Identity) PrivateKeyByID(keyID string) ([]byte, error) {
	for _, key := range i.LocalKeys {
		if key.KeyID == keyID {
			return append([]byte(nil), key.PrivateKey...), nil
		}
	}
	return nil, fmt.Errorf("private key not found: %s", keyID)
}
