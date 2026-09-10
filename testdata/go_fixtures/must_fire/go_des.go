package mustfire

import "crypto/des"

func NewLegacyCipher(key []byte) (interface{}, error) {
	return des.NewTripleDESCipher(key)
}
