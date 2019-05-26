package chefcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

// CipherV3 the v3 cipher used
const CipherV3 = "aes-256-gcm"

// EncryptedDataBagV3 version 3 encrypted databag
type EncryptedDataBagV3 struct {
	EncryptedData string `json:"encrypted_data"`
	IV            string `json:"iv"`
	AuthTag       string `json:"auth_tag"`
	Version       int    `json:"version"`
	Cipher        string `json:"cipher"`
}

// Decrypt decrypts the v3 databag
func (c *EncryptedDataBagV3) Decrypt(key []byte, target interface{}) error {
	tgtVal := reflect.ValueOf(target)
	if tgtVal.Kind() != reflect.Ptr || tgtVal.IsNil() {
		return fmt.Errorf("target must be a non-nil pointer")
	} else if len(key) == 0 {
		return fmt.Errorf("key must be a non-empty byte array")
	}

	var res map[string]interface{}
	keyHash := hashKey(key)

	// create a new AES cipher
	block, err := aes.NewCipher(keyHash)
	if err != nil {
		return err
	}

	// decode the encrypted data from base64
	data, err := base64.StdEncoding.DecodeString(c.EncryptedData)
	if err != nil {
		return err
	}

	// decode iv from base64
	nonce, err := base64.StdEncoding.DecodeString(c.IV)
	if err != nil {
		return err
	}

	// decode the auth tag from base64
	tag, err := base64.StdEncoding.DecodeString(c.AuthTag)
	if err != nil {
		return err
	}

	// add the tag to the end of the data
	ciphertext := append(data, tag...)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// decrypt the data
	decrypted, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil
	}

	// unmarshal the json
	err = json.Unmarshal(decrypted, &res)
	if err != nil {
		return err
	}

	// look for the json wrapper
	val, ok := res["json_wrapper"]
	if !ok {
		return fmt.Errorf("failed to decrypt databag")
	}

	// assign the value to the target
	reflect.ValueOf(target).Elem().Set(reflect.ValueOf(&val).Elem())
	return nil
}

// EncryptDataBagV3 encrypts a databag with the v1 specification
func EncryptDataBagV3(key, jsonData []byte) (*EncryptedDataBagV3, error) {
	keyHash := hashKey(key)

	// create a new AES cipher
	block, err := aes.NewCipher(keyHash)
	if err != nil {
		return nil, err
	}

	// wrap the data in json. data should be json formatted
	wrappedData := fmt.Sprintf("{\"json_wrapper\":%s}", jsonData)

	// generate a nonce
	nonce := make([]byte, gcmStandardNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// create a GCM cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// generate the ciphertext
	ciphertext := aesgcm.Seal(nil, nonce, []byte(wrappedData), nil)

	// get the encrypted data by stripping the authTag
	encryptedData := ciphertext[:len(ciphertext)-gcmTagSize]

	// get the auth tag from the end
	authTag := ciphertext[len(ciphertext)-gcmTagSize:]

	// create a new v3 data bag and return it
	secret := EncryptedDataBagV3{
		EncryptedData: base64.StdEncoding.EncodeToString(encryptedData),
		IV:            base64.StdEncoding.EncodeToString(nonce),
		AuthTag:       base64.StdEncoding.EncodeToString(authTag),
		Version:       3,
		Cipher:        CipherV3,
	}
	return &secret, nil
}