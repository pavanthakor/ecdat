package mustfire;

import java.security.PublicKey;
import java.security.Signature;

/**
 * The VERIFY side of a JCA signature. The Signature arrives configured, so this
 * file holds only initVerify + verify -- the calls java-signature-verify
 * matches. getInstance lives elsewhere on purpose (see the answer key).
 */
public class JavaSignatureVerify {
    public boolean check(Signature verifier, PublicKey key, byte[] data, byte[] sig)
            throws Exception {
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(sig);
    }
}
