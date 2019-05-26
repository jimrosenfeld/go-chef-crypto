package chefcrypto

import (
	"bytes"
	"crypto/aes"
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

// pkcs7Pad appends padding.
// from https://github.com/Luzifer/go-openssl/blob/master/openssl.go
func pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// pkcs7Unpad returns slice of the original data without padding.
// from https://github.com/Luzifer/go-openssl/blob/master/openssl.go
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padlen], nil
}

var padPatterns [aes.BlockSize + 1][]byte

// pkcs7Unpad returns slice of the original data without padding.
func pkcs7Unpad2(data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > aes.BlockSize || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	if !bytes.Equal(padPatterns[padlen], data[len(data)-padlen:]) {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-padlen], nil
}
