package mustfire

import "github.com/golang-jwt/jwt/v5"

func Sign(claims jwt.Claims, key interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}
