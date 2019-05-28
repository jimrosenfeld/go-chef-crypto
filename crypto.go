package chefcrypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const gcmStandardNonceSize = 12
const gcmTagSize = 16

// IsEncryptedDataBagItem determines if the databag is encrypted and if so what version
func IsEncryptedDataBagItem(data []byte) (bool, int, *map[string]interface{}) {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return false, -1, &m
	}

	// check the required keys
	version, vOK := m["version"]
	_, dOK := m["encrypted_data"]
	_, iOK := m["iv"]
	_, cOK := m["cipher"]

	// if any of the fields are missing return false
	if !vOK || !dOK || !iOK || !cOK {
		return false, -1, nil
	}

	// return true with the version and the map
	return true, version.(int), &m
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

// hash the key
func hashKey(key []byte) []byte {
	hash := sha256.New()
	hash.Write(key)
	return hash.Sum(nil)
}

// create a hmac from the encrypted data and key
func encryptedDataHMAC(keyHash, encryptedData []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, keyHash)
	if _, err := mac.Write(encryptedData); err != nil {
		return nil, err
	}
	sum := mac.Sum(nil)
	return sum, nil
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

// formats data as base 64 in lines of 60 characters
// with a trailing new line (why 60?)
func formatBase64(data []byte) string {
	b64str := base64.StdEncoding.EncodeToString(data)
	rx := regexp.MustCompile(`.{1,60}`)
	blocks := rx.FindAllString(b64str, -1)
	return fmt.Sprintf("%s\n", strings.Join(blocks, "\n"))
}
