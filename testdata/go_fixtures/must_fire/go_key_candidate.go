package mustfire

// must_fire: go-hardcoded-key-candidate (ADR-0034) -- a key-ish name holding a
// high-entropy 32- or 64-character hex literal with no sink: a CANDIDATE at
// low confidence for an analyst to confirm, never asserted. Random filler.

var backupEncryptionKey = "01ee996b12ef5fc9774d137d3ed930a2"

const webhookSigningSecret = "c68f7163878626ee73572778289cc2236613b82a6c980ab11a359e4f58444493"

func Secrets() (string, string) { return backupEncryptionKey, webhookSigningSecret }
