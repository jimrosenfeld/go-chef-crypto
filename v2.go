package chefcrypto

// EncryptedDataBagV2 version 2 encrypted databag
type EncryptedDataBagV2 struct {
	EncryptedData string `json:"encrypted_data"`
	HMAC          string `json:"hmac"`
	IV            string `json:"iv"`
	Version       int    `json:"version"`
	Cipher        string `json:"cipher"`
}

// Decrypt decrypts the v2 databag
func (c *EncryptedDataBagV2) Decrypt(key []byte, target interface{}) error {
	return nil
}

// EncryptDataBagV2 encrypts a databag with the v2 specification
func EncryptDataBagV2(key, data []byte) (*EncryptedDataBagV2, error) {
	return nil, nil
}
