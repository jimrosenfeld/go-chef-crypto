package chefcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// CipherV2 the v2 cipher used
const CipherV2 = "aes-256-cbc"

// EncryptedDataBagV2 version 2 encrypted databag
type EncryptedDataBagV2 struct {
	EncryptedData string `json:"encrypted_data"`
	HMAC          string `json:"hmac"`
	IV            string `json:"iv"`
	Version       int    `json:"version"`
	Cipher        string `json:"cipher"`
}

// TODO this is not calculating correctly
// create a hmac from the encrypted data and key
func encryptedDataHMAC(key, encryptedData []byte) (string, error) {
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(encryptedData); err != nil {
		return "", err
	}
	sum := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum), nil
}

// Decrypt decrypts the v2 databag
func (c *EncryptedDataBagV2) Decrypt(key []byte, target interface{}) error {
	keyHash := hashKey(key)

	// get the hmac
	h, err := encryptedDataHMAC(keyHash, []byte(c.EncryptedData))
	if err != nil {
		return err
	}

	fmt.Printf("\n\nCALC: %q\nACTU: %q\n\n", h, c.HMAC)

	if h != c.HMAC {
		return fmt.Errorf("the hmac could not be validated")
	}

	// since v1 and v2 are the same except the hmac validation
	// just create a v1 databag and decrypt that
	databag := EncryptedDataBagV1{
		EncryptedData: c.EncryptedData,
		IV:            c.IV,
		Version:       1,
		Cipher:        CipherV1,
	}

	return databag.Decrypt(key, target)
}

// EncryptDataBagV2 encrypts a databag with the v2 specification
func EncryptDataBagV2(key, data []byte) (*EncryptedDataBagV2, error) {
	// since v1 and v2 are the same encrypt using v1
	d, err := EncryptDataBagV1(key, data)
	if err != nil {
		return nil, err
	}

	// generate the hmac
	h, err := encryptedDataHMAC(key, []byte(d.EncryptedData))
	if err != nil {
		return nil, err
	}

	// create a new v2 databag
	databag := EncryptedDataBagV2{
		EncryptedData: d.EncryptedData,
		HMAC:          h,
		IV:            d.IV,
		Version:       2,
		Cipher:        CipherV2,
	}

	return &databag, nil
}
