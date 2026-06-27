package attestation

import (
	"crypto/ed25519"
	"time"

	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/pkg/types"
)

func New(issuerID, issuerKeyID, subjectID, claimType string, claimPayload map[string]interface{}, validFor time.Duration, evidenceRef string) (types.Attestation, error) {
	now := time.Now().UTC()
	att := types.Attestation{Version: "1", IssuerID: issuerID, IssuerKeyID: issuerKeyID, SubjectID: subjectID, ClaimType: claimType, ClaimPayload: claimPayload, IssuedAt: now, ValidFrom: now, ValidTo: now.Add(validFor), EvidenceRef: evidenceRef}
	cid, err := AttestationCID(att)
	if err != nil {
		return types.Attestation{}, err
	}
	att.CID = cid
	return att, nil
}

// AttestationCID recomputes the content-addressed CID of an attestation from
// its signed fields. It is the single source of truth shared by New and by
// integrity checks on fetched objects.
func AttestationCID(att types.Attestation) (string, error) {
	base := map[string]interface{}{
		"version":      att.Version,
		"issuerId":     att.IssuerID,
		"issuerKeyId":  att.IssuerKeyID,
		"subjectId":    att.SubjectID,
		"claimType":    att.ClaimType,
		"claimPayload": att.ClaimPayload,
		"issuedAt":     att.IssuedAt.Format(time.RFC3339Nano),
		"validFrom":    att.ValidFrom.Format(time.RFC3339Nano),
		"validTo":      att.ValidTo.Format(time.RFC3339Nano),
		"evidenceRef":  att.EvidenceRef,
	}
	encoded, err := icrypto.CanonicalJSON(base)
	if err != nil {
		return "", err
	}
	return icrypto.HashString("attestation:" + icrypto.HashBytes(encoded)), nil
}

func Sign(attestation *types.Attestation, priv ed25519.PrivateKey) error {
	payload := signaturePayload(*attestation)
	encoded, err := icrypto.CanonicalJSON(payload)
	if err != nil {
		return err
	}
	attestation.Signature = icrypto.SignBytes(priv, encoded)
	return nil
}

func Verify(attestation types.Attestation, pub ed25519.PublicKey) bool {
	if !attestation.ValidTo.IsZero() && time.Now().UTC().After(attestation.ValidTo) {
		return false
	}
	if !attestation.ValidFrom.IsZero() && time.Now().UTC().Before(attestation.ValidFrom) {
		return false
	}
	payload := signaturePayload(attestation)
	encoded, err := icrypto.CanonicalJSON(payload)
	if err != nil {
		return false
	}
	return icrypto.VerifyBytes(pub, encoded, attestation.Signature)
}

func signaturePayload(attestation types.Attestation) map[string]interface{} {
	payload := map[string]interface{}{
		"cid":          attestation.CID,
		"version":      attestation.Version,
		"issuerId":     attestation.IssuerID,
		"issuerKeyId":  attestation.IssuerKeyID,
		"subjectId":    attestation.SubjectID,
		"claimType":    attestation.ClaimType,
		"claimPayload": attestation.ClaimPayload,
		"issuedAt":     attestation.IssuedAt.Format(time.RFC3339Nano),
		"validFrom":    attestation.ValidFrom.Format(time.RFC3339Nano),
		"evidenceRef":  attestation.EvidenceRef,
	}
	if !attestation.ValidTo.IsZero() {
		payload["validTo"] = attestation.ValidTo.Format(time.RFC3339Nano)
	}
	return payload
}
