package mustfire;

// must_fire: java-hardcoded-key-candidate (ADR-0034) -- a key-ish name holding
// a high-entropy 32- or 64-character hex literal with no sink: a CANDIDATE at
// low confidence for an analyst to confirm, never asserted. Random filler.
public class JavaKeyCandidate {
    private static final String BACKUP_ENCRYPTION_KEY = "f729627e7d7959646ec0ce89791082d0";

    private static final String WEBHOOK_SIGNING_SECRET =
        "a1c20c2b1b7f5b48838cd84fb63c9a61a2494d231a7b3d056e31e2add0f2911e";

    public int describe() {
        return BACKUP_ENCRYPTION_KEY.length() + WEBHOOK_SIGNING_SECRET.length();
    }
}
