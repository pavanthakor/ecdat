package mustfire;

import java.security.PublicKey;
import java.security.Signature;

/**
 * must_fire: java-signature-rsa, REFINED to usage=verify (ADR-0037), and
 * java-signature-verify at initVerify.
 *
 * getInstance and initVerify on the same variable in one method: the use site
 * says this Signature VERIFIES. Before ADR-0037 it was inventoried as a signer.
 */
public class JavaSignatureVerifier {
    public boolean check(PublicKey key, byte[] data, byte[] sig) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(sig);
    }
}
