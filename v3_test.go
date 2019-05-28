package chefcrypto

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestV3Full(t *testing.T) {
	// generate a key for encryption
	key, _ := NewSecretKey(512)

	// encrypt the data
	databag, err := EncryptDataBagItemV3(key, []byte(testSecretData))
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	// attempt to decrypt the data to an interface
	var value interface{}
	if err := databag.Decrypt(key, &value); err != nil {
		t.Errorf("%v", err)
		return
	}

	if !reflect.DeepEqual(value, testSecret) {
		t.Error("decrypted data did not match source")
		return
	}
}

func TestV3Decrypt(t *testing.T) {
	var databag EncryptedDataBagItemV3
	var value interface{}
	var data interface{}
	if err := json.Unmarshal([]byte(testDataBagV3), &databag); err != nil {
		t.Error("failed to unmarshal v3 data bag")
		return
	}

	if err := databag.Decrypt([]byte(testSecretKey), &value); err != nil {
		t.Error("failed to decrypt v3 data bag")
		return
	}
	if value.(string) != testSecret {
		t.Error("invalid data bag data")
		return
	}
	// test decrypt method
	if err := Decrypt([]byte(testSecretKey), []byte(testDataBagV3), &data); err != nil {
		t.Errorf("%v", err)
		return
	}
	if !reflect.DeepEqual(testSecret, data) {
		t.Error("v3 data improperly decrypted")
		return
	}
}
