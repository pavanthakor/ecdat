package mustfire;

import java.security.Signature;

public class JavaSignatureEcdsa {
    public Signature signer() throws Exception {
        return Signature.getInstance("SHA256withECDSA");
    }
}
