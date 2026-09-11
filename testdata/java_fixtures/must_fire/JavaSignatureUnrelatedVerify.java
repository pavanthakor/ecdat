package mustfire;

import java.security.Signature;

/**
 * must_fire: java-signature-rsa, NOT refined (ADR-0037).
 *
 * A verify() in the same method -- but on a DIFFERENT Signature. The fresh one
 * is handed on without a direction, so it keeps the rule's default. The
 * refinement follows the variable, not the method.
 */
public class JavaSignatureUnrelatedVerify {
    public boolean check(Signature other, byte[] sig) throws Exception {
        Signature fresh = Signature.getInstance("SHA256withRSA");
        keep(fresh);
        return other.verify(sig);
    }

    private void keep(Signature signature) {
    }
}
