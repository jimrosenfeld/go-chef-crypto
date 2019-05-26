package chefcrypto

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestV1(t *testing.T) {
	// generate a key for encryption
	key, _ := NewSecretKey(512)

	// encrypt the data
	databag, err := EncryptDataBagV1(key, []byte(data1))
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
	}
}
