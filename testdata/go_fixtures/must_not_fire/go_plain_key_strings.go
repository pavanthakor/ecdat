// must_not_fire (ADR-0034): the Juice Shop false-positive class, in Go. Every
// name reads like a key; every value is a context key, cookie name, header,
// environment-variable NAME or cache prefix. Nothing may fire.
package decoys

import (
	"context"
	"net/http"
	"os"
)

type ctxKey string

const userKey ctxKey = "user"

const sessionCookieKey = "session_id"

const apiKeyHeader = "X-Api-Key"

const apiKeyEnv = "PAYMENTS_API_KEY"

var cacheKeyPrefix = "basket:"

var passwordField = "password"

func User(ctx context.Context) any { return ctx.Value(userKey) }

func Session(r *http.Request) (*http.Cookie, error) { return r.Cookie(sessionCookieKey) }

func APIKey(r *http.Request) string { return r.Header.Get(apiKeyHeader) }

func FromEnv() string { return os.Getenv(apiKeyEnv) }

func CacheKey(id string) string { return cacheKeyPrefix + id + passwordField }
