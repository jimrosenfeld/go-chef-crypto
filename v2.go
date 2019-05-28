package chefcrypto

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"reflect"
)

// CipherV2 the v2 cipher used
const CipherV2 = "aes-256-cbc"

// EncryptedDataBagItemV2 version 2 encrypted databag
type EncryptedDataBagItemV2 struct {
	EncryptedData string `json:"encrypted_data"`
	HMAC          string `json:"hmac"`
	IV            string `json:"iv"`
	Version       int    `json:"version"`
	Cipher        string `json:"cipher"`
}

// Decrypt decrypts the v2 databag
func (c *EncryptedDataBagItemV2) Decrypt(key []byte, target interface{}) error {
	tgtVal := reflect.ValueOf(target)
	if tgtVal.Kind() != reflect.Ptr || tgtVal.IsNil() {
		return fmt.Errorf("target must be a non-nil pointer")
	} else if len(key) == 0 {
		return fmt.Errorf("key must be a non-empty byte array")
	} else if c.Cipher != CipherV2 {
		return fmt.Errorf("invalid databag cipher %q, expected %q", c.Cipher, CipherV2)
	}

	keyHash := hashKey(key)

	// generate an hmac from the encrypted data and key
	hmacCheck, err := encryptedDataHMAC(keyHash, []byte(c.EncryptedData))
	if err != nil {
		return err
	}
	// decode the encrypted data from base64
	hmacEnc, err := base64.StdEncoding.DecodeString(c.HMAC)
	if err != nil {
		return err
	}

	if !hmac.Equal(hmacCheck, hmacEnc) {
		return fmt.Errorf("the hmac could not be validated")
	}

	// since v1 and v2 are the same except the hmac validation
	// just create a v1 databag and decrypt that
	databag := EncryptedDataBagItemV1{
		EncryptedData: c.EncryptedData,
		IV:            c.IV,
		Version:       1,
		Cipher:        CipherV1,
	}

	return databag.Decrypt(key, target)
}

// EncryptDataBagItemV2 encrypts a databag with the v2 specification
func EncryptDataBagItemV2(key, data []byte) (*EncryptedDataBagItemV2, error) {
	// since v1 and v2 are the same encrypt using v1
	d, err := EncryptDataBagItemV1(key, data)
	if err != nil {
		return nil, err
	}

	// generate the hmac
	keyHash := hashKey(key)
	h, err := encryptedDataHMAC(keyHash, []byte(d.EncryptedData))
	if err != nil {
		return nil, err
	}

	// create a new v2 databag
	databag := EncryptedDataBagItemV2{
		EncryptedData: d.EncryptedData,
		HMAC:          formatBase64(h),
		IV:            d.IV,
		Version:       2,
		Cipher:        CipherV2,
	}

	return &databag, nil
}
