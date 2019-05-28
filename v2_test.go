package chefcrypto

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestV2Full(t *testing.T) {
	// generate a key for encryption
	key, _ := NewSecretKey(512)

	// encrypt the data
	databag, err := EncryptDataBagItemV2(key, []byte(data1))
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

	// test the output
	var check interface{}

	// check the source data against the decrypted
	err = json.Unmarshal([]byte(data1), &check)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	if !reflect.DeepEqual(value, check) {
		t.Error("decrypted data did not match source")
		return
	}
}

func TestV2Decrypt(t *testing.T) {
	var databag EncryptedDataBagItemV2
	var value interface{}
	if err := json.Unmarshal([]byte(testDataBagV2), &databag); err != nil {
		t.Error("failed to unmarshal v2 data bag")
		return
	}

	if err := databag.Decrypt([]byte(testSecretKey), &value); err != nil {
		t.Error("failed to decrypt v2 data bag")
		return
	}
	if value.(string) != "Hello, World!" {
		t.Error("invalid data bag data")
		return
	}
}
