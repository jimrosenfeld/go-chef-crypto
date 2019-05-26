package chefcrypto

// EncryptedDataBagV1 version 1 encrypted databag
type EncryptedDataBagV1 struct {
	EncryptedData string `json:"encrypted_data"`
	IV            string `json:"iv"`
	Version       int    `json:"version"`
	Cipher        string `json:"cipher"`
}

// Decrypt decrypts the v1 databag
func (c *EncryptedDataBagV1) Decrypt(key []byte, target interface{}) error {
	return nil
}

// EncryptDataBagV1 encrypts a databag with the v1 specification
func EncryptDataBagV1(key, data []byte) (*EncryptedDataBagV1, error) {
	return nil, nil
}
