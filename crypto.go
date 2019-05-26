package chefcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

const gcmStandardNonceSize = 12
const gcmTagSize = 16

// hash the key
func hashKey(key []byte) []byte {
	hash := sha256.New()
	hash.Write(key)
	return hash.Sum(nil)
}

// NewSecretKey generates a new secret key of specified length
func NewSecretKey(length int) ([]byte, error) {
	if length%128 > 0 {
		return nil, fmt.Errorf("key length must be a multiple of 128")
	}

	key := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	return key, nil
}

// NewSecretKeyBase64 generates a new secret key of specified length
func NewSecretKeyBase64(length int) (*string, error) {
	key, err := NewSecretKey(length)
	if err != nil {
		return nil, err
	}
	b64key := base64.StdEncoding.EncodeToString(key)
	return &b64key, nil
}
