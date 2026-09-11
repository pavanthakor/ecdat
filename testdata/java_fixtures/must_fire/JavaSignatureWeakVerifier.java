package mustfire;

import java.security.PublicKey;
import java.security.Signature;

/**
 * must_fire: java-signature-weak-hash, REFINED to usage=verify (ADR-0037), and
 * java-signature-verify at initVerify.
 *
 * Declared first and assigned later -- the second shape ADR-0037's STEP 0
 * measured. A legacy SHA-1 verifier stays flagged: verifying a forgeable
 * signature accepts the forgery.
 */
public class JavaSignatureWeakVerifier {
    public boolean legacyCheck(PublicKey key, byte[] data, byte[] sig) throws Exception {
        Signature verifier;
        verifier = Signature.getInstance("SHA1withRSA");
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(sig);
    }
}
