package mustfire;

import java.security.PrivateKey;
import java.security.Signature;

/**
 * must_fire: java-signature-ecdsa, CONFIRMED as usage=sign by its use site
 * (ADR-0037): initSign and sign on the same variable in one method.
 */
public class JavaSignatureSigner {
    public byte[] produce(PrivateKey key, byte[] data) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(key);
        signer.update(data);
        return signer.sign();
    }
}
