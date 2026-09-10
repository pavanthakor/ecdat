package mustfire

// must_fire: go-hardcoded-key (ADR-0034) -- literals that REACH a key
// parameter. The sentinels must reach no Finding.

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/golang-jwt/jwt/v5"
)

// High-entropy, key-ish AND reaching a sink: go-hardcoded-key-candidate
// matches this declaration too, and the scanner folds it into the sink
// finding -- one key, one finding.
var webhookKey = "954649cdbbb849faef3780730539868c"

func MacOf(data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(webhookKey))
	mac.Write(data)
	return mac.Sum(nil)
}

// Inline at the sink.
func LegacyMac(data []byte) []byte {
	mac := hmac.New(sha256.New, []byte("GOSINKSENTINELinlineHmacKey0123"))
	mac.Write(data)
	return mac.Sum(nil)
}

// A local, into golang-jwt's SignedString.
func Issue(token *jwt.Token) (string, error) {
	signingSecret := []byte("GOSINKSENTINELjwtSigningSecret01")
	return token.SignedString(signingSecret)
}
