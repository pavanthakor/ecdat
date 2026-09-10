package mustfire

import "crypto/sha1"

func Digest(data []byte) [20]byte {
	return sha1.Sum(data)
}
