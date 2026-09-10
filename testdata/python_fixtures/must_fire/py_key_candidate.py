"""must_fire: py-hardcoded-key-candidate (ADR-0034).

A key-ish name holding a high-entropy 32- or 64-character hex literal with no
sink: a CANDIDATE at low confidence for an analyst to confirm, never asserted.
The literals are random filler.
"""

BACKUP_ENCRYPTION_KEY = "5311553b827b1eb7ea26c27891eb47d4"
WEBHOOK_SIGNING_SECRET = "d1747741165638f9421860a1737edc342128fed40f13d9018c8f99ebf86fe719"
