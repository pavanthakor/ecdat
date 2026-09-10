// Java that MUST NOT produce a single Finding.
//
// Every entry is a plausible false positive: prose naming an algorithm, an
// identifier that reads like a digest, a name-scoped RNG rule's non-key use,
// and the string "AES" in a non-cryptographic position.
package mustnotfire;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class Decoys {

    // RSA, MD5 and RC4 are named in this comment, and
    // KeyPairGenerator.getInstance("RSA") appears here too. A comment is
    // documentation, not a call site: nothing may fire on it.
    private static final String DOCUMENTATION =
        "we migrated off MD5 and RC4 in 2019; RSA-2048 is still in use";

    // Identifiers that read like crypto but hold nothing secret.
    private String md5Column = "legacy_md5_column";
    private String cipherName = "display-name";
    private String sha1Migration = "completed";

    // "AES" as a MAP KEY and a label -- a string, in no cryptographic call.
    public Map<String, String> algorithmLabels() {
        Map<String, String> labels = new HashMap<>();
        labels.put("AES", "Advanced Encryption Standard");
        labels.put("DES", "retired 2005");
        labels.put("SHA-1", "retired 2017");
        return labels;
    }

    // A name-scoped RNG rule must NOT fire here: jitter is not a key, token,
    // secret or nonce.
    public long backoffJitter(int attempt) {
        Random rng = new Random();
        long jitter = rng.nextInt(100);
        return attempt * 1000L + jitter;
    }

    // Shuffling a display list is not key generation either.
    public int pickBanner(String[] banners) {
        Random rng = new Random();
        int index = rng.nextInt(banners.length);
        return index;
    }

    public String describe() {
        return DOCUMENTATION + md5Column + cipherName + sha1Migration;
    }
}
