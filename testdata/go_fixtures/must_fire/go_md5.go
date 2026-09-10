package mustfire

import "crypto/md5"

func Digest(data []byte) [16]byte {
	return md5.Sum(data)
}
