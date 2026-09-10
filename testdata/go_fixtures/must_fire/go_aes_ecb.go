package mustfire

import "crypto/aes"

// ECB: no IV, identical plaintext blocks produce identical ciphertext blocks.
func EncryptECB(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
	block.Encrypt(out, plaintext)
	return out, nil
}
