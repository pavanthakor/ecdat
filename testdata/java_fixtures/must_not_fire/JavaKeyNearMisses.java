// must_not_fire (ADR-0034): near misses. Each fails exactly ONE corroboration
// signal and must not fire.
package mustnotfire;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class JavaKeyNearMisses {
    // Right name, right length, no entropy.
    private static final String REPEATING_KEY = "deadbeefdeadbeefdeadbeefdeadbeef";

    // Right name, random, 31 characters: under the 32-character bar.
    private static final String SHORT_HEX_KEY = "1dfc3522f276cc5d214cf8a0066b867";

    // Random and 64 characters, but nothing in the NAME says key: a digest.
    private static final String RELEASE_CHECKSUM =
        "cc675e3a6bd1c4d75ae9c88227bcfbeb340590c522807bc3e017710aeff4b727";

    // A KDF's output is not its salt: `taint_assume_safe_functions` stops the
    // salt literal flowing through the factory into the key spec.
    public SecretKeySpec fromPassword(char[] password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] derived = factory.generateSecret(
            new PBEKeySpec(password, "JAVANEARMISSstaticSalt".getBytes(), 600000, 256)).getEncoded();
        return new SecretKeySpec(derived, "AES");
    }

    // Assembled from a constant and a runtime value: a part is not the key.
    public SecretKeySpec tenantKey(String tenantSecret) {
        return new SecretKeySpec(("JAVANEARMISSprefix" + tenantSecret).getBytes(), "AES");
    }

    public String names() {
        return REPEATING_KEY + SHORT_HEX_KEY + RELEASE_CHECKSUM;
    }
}
