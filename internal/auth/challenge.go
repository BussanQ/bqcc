package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/internal/identity"
	"github.com/example/decentid/pkg/types"
)

func NewChallenge(identityID string, ttl time.Duration) (types.Challenge, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return types.Challenge{}, err
	}
	now := time.Now().UTC()
	return types.Challenge{
		IdentityID: identityID,
		Nonce:      base64.StdEncoding.EncodeToString(raw),
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
	}, nil
}

func SignChallenge(challenge types.Challenge, signerKeyID string, identityState *identity.Identity) (types.ChallengeResponse, error) {
	if challenge.IdentityID != identityState.Document.ID {
		return types.ChallengeResponse{}, identityErr("challenge identity does not match local identity")
	}
	if signerKeyID == "" {
		signerKeyID = identityState.DeviceKeyID()
	}
	if _, err := identity.ResolveKey(identityState.Document, signerKeyID); err != nil {
		return types.ChallengeResponse{}, err
	}
	isDevice := false
	for _, key := range identityState.Document.ActiveKeys {
		if key.ID == signerKeyID && key.Role == types.KeyRoleDevice && key.RevokedAt.IsZero() {
			isDevice = true
			break
		}
	}
	if !isDevice {
		return types.ChallengeResponse{}, identityErr("signer key is not an active device key")
	}
	priv, err := identityState.SigningPrivateKeyByID(signerKeyID)
	if err != nil {
		return types.ChallengeResponse{}, err
	}
	encoded, err := icrypto.CanonicalJSON(challengePayload(challenge))
	if err != nil {
		return types.ChallengeResponse{}, err
	}
	return types.ChallengeResponse{
		Challenge:   challenge,
		SignerKeyID: signerKeyID,
		Signature:   icrypto.SignBytes(priv, encoded),
	}, nil
}

func VerifyChallenge(response types.ChallengeResponse, doc types.IdentityDocument) bool {
	if time.Now().UTC().After(response.Challenge.ExpiresAt) {
		return false
	}
	if response.Challenge.IdentityID != doc.ID {
		return false
	}
	isDevice := false
	for _, key := range doc.ActiveKeys {
		if key.ID == response.SignerKeyID && key.Role == types.KeyRoleDevice && key.RevokedAt.IsZero() {
			isDevice = true
			break
		}
	}
	if !isDevice {
		return false
	}
	pub, err := identity.ResolveKey(doc, response.SignerKeyID)
	if err != nil {
		return false
	}
	encoded, err := icrypto.CanonicalJSON(challengePayload(response.Challenge))
	if err != nil {
		return false
	}
	return icrypto.VerifyBytes(pub, encoded, response.Signature)
}

// challengePayload builds the canonical pre-image signed/verified for a
// challenge. Shared by SignChallenge and VerifyChallenge.
func challengePayload(challenge types.Challenge) map[string]interface{} {
	return map[string]interface{}{
		"identityId": challenge.IdentityID,
		"nonce":      challenge.Nonce,
		"issuedAt":   challenge.IssuedAt.Format(time.RFC3339Nano),
		"expiresAt":  challenge.ExpiresAt.Format(time.RFC3339Nano),
	}
}

func identityErr(message string) error {
	return errors.New(message)
}
