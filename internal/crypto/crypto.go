package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/scrypt"
)

const (
	passphraseSaltSize = 16
	scryptN            = 1 << 15
	scryptR            = 8
	scryptP            = 1
	scryptKeyLen       = 32
)

// EncryptWithPassphrase derives a key from passphrase via scrypt and seals the
// plaintext with AES-256-GCM. Output layout: salt(16) || nonce(12) || ciphertext.
func EncryptWithPassphrase(plaintext []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase required")
	}
	salt := make([]byte, passphraseSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, salt)
	out := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptWithPassphrase reverses EncryptWithPassphrase. A wrong passphrase or
// tampered blob fails GCM authentication and returns an error.
func DecryptWithPassphrase(blob []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase required")
	}
	if len(blob) < passphraseSaltSize {
		return nil, errors.New("backup data too short")
	}
	salt := blob[:passphraseSaltSize]
	derived, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(blob) < passphraseSaltSize+nonceSize {
		return nil, errors.New("backup data too short")
	}
	nonce := blob[passphraseSaltSize : passphraseSaltSize+nonceSize]
	ciphertext := blob[passphraseSaltSize+nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, salt)
}

func GenerateEd25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func GenerateX25519Keypair() ([]byte, []byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.PublicKey().Bytes(), priv.Bytes(), nil
}

func PublicKeyString(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

func PrivateKeyString(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv)
}

func BytesString(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func ParseBytes(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}

func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := ParseBytes(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length")
	}
	return ed25519.PublicKey(decoded), nil
}

func ParsePrivateKey(value string) (ed25519.PrivateKey, error) {
	decoded, err := ParseBytes(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length")
	}
	return ed25519.PrivateKey(decoded), nil
}

func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func HashString(value string) string {
	return HashBytes([]byte(value))
}

func DIDFromPublicKey(pub ed25519.PublicKey) string {
	return "did:p2p:" + HashBytes(pub)
}

func SignBytes(priv ed25519.PrivateKey, payload []byte) string {
	sig := ed25519.Sign(priv, payload)
	return base64.StdEncoding.EncodeToString(sig)
}

func VerifyBytes(pub ed25519.PublicKey, payload []byte, signature string) bool {
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, payload, decoded)
}

func EncryptForRecipient(plaintext, recipientPublicKey []byte) (ciphertext, ephemeralPublicKey, nonce []byte, err error) {
	curve := ecdh.X25519()
	recipient, err := curve.NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	sharedSecret, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, nil, nil, err
	}
	key := sha256.Sum256(sharedSecret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, ephemeral.PublicKey().Bytes(), nonce, nil
}

func DecryptForRecipient(ciphertext, ephemeralPublicKey, nonce, recipientPrivateKey []byte) ([]byte, error) {
	curve := ecdh.X25519()
	ephemeral, err := curve.NewPublicKey(ephemeralPublicKey)
	if err != nil {
		return nil, err
	}
	recipient, err := curve.NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := recipient.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(sharedSecret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func CanonicalJSON(value interface{}) ([]byte, error) {
	normalized, err := normalize(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func normalize(value interface{}) (interface{}, error) {
	switch v := value.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		ordered := make([]interface{}, 0, len(keys)*2)
		for _, key := range keys {
			nv, err := normalize(v[key])
			if err != nil {
				return nil, err
			}
			ordered = append(ordered, key, nv)
		}
		return ordered, nil
	case []interface{}:
		items := make([]interface{}, 0, len(v))
		for _, item := range v {
			nv, err := normalize(item)
			if err != nil {
				return nil, err
			}
			items = append(items, nv)
		}
		return items, nil
	default:
		return v, nil
	}
}
