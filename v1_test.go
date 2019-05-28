package chefcrypto

import (
	"encoding/json"
	"reflect"
	"testing"
)

var data1 = `{"foo":"bar"}`
var testSecretKey = "o1mC2dputDeYkHpcoAw42+Luzd2l1sl4yTORmVu5opmlBViugejYhmjCYwVlbROizekeh2MWjHjk7hdgiPznEivQcVoArUHvSrOYmWQdYSxH7ad8hQ9NlceX6O0HHA2OWwn5pROQ4Lu7A/QhHIjFiJ/Y16AQGbzYG70DpByNGmBGToT8izVo8C/4EVYvI3Dmc4vwgxfqZ2BXxfQrBo6oPF9Lr0/N25iqKFLGxeYtGSWTFdSWO4tFlAfc7w5W30Zv/GQYm1lRNOlsbgYP7eFiwEOGNgGwE3PC5ad+2hX1U8wbcd4k9P4QOyURlfKFwOOC5Ei+Fior8cLOlCVshItbRf7OC8PC6rH81o498WhFBvzdYtDQ+tzDPgQuFtBNzq1g9A5Bo6DmmMFAIR3rRDQ1aFdwTUfaluC+cbYqJFZfTwsuZKfU1vvDpXaFL94sOkKEKlDSzawNOw3CyxYQ4O0nJCszQ372lFbhYcwqIe3K19uws2v+H3/DGhfAE5PGbKAuHOvtLAMPVMmzozNjAKJaNV/kxtGNbts9lD4kFPWixts4N1vk5TER/Lxo/Fz4b2RLv0XKCDYN7T3WFcR1F6L78DRyyVTOkm95BeueBNmU7pmn3jtHkOmeeFjUWQ+yPBkI2FdinzMjlKwzdsh5VuZDHO36NIxdl8LiAGWD1UEJjtY="
var testDataBagV1 = `{
	"encrypted_data": "ERIOejLvPUer8yNC6aZncHb87flvVE5ykvKg+dy4/LLB2tnWxa/FY7RYHJRt\nb6f7\n",
	"iv": "5GsbEoOtSWEFB0EUKj/vJQ==\n",
	"version": 1,
	"cipher": "aes-256-cbc"
}`
var testDataBagV2 = `{
	"encrypted_data": "FopWuuNSHZnCyaQXM1UoP2Jo/N/JeEh9VXcL9pq5fWxe/SRGg7Q3wy0xX11p\nBEu+\n",
	"hmac": "VUPSuUwaNkyVkBTk7NHLSrB0vzC7N7dmoTa75Nu4rbs=\n",
	"iv": "wAQfq5pxwyVG5kOULinpXg==\n",
	"version": 2,
	"cipher": "aes-256-cbc"
}`
var testDataBagV3 = `{
	"encrypted_data": "obL5wd4cXbiJcjC/4FcjoOrq9iqF8c26ZgEgUlSmWI0=\n",
	"iv": "rAR84VLto9vB9+wt\n",
	"auth_tag": "Jott8Th0Ybr0nB8lkYnIKw==\n",
	"version": 3,
	"cipher": "aes-256-gcm"
}`

func TestV1Full(t *testing.T) {
	// generate a key for encryption
	key, _ := NewSecretKey(512)

	// encrypt the data
	databag, err := EncryptDataBagItemV1(key, []byte(data1))
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

func TestV1Decrypt(t *testing.T) {
	var databag EncryptedDataBagItemV1
	var value interface{}
	if err := json.Unmarshal([]byte(testDataBagV1), &databag); err != nil {
		t.Error("failed to unmarshal v1 data bag")
		return
	}

	if err := databag.Decrypt([]byte(testSecretKey), &value); err != nil {
		t.Error("failed to decrypt v1 data bag")
		return
	}
	if value.(string) != "Hello, World!" {
		t.Error("invalid data bag data")
		return
	}
}
