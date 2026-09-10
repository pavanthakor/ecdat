package mustfire;

import java.security.Signature;

public class JavaSignatureRsa {
    public Signature signer() throws Exception {
        return Signature.getInstance("SHA256withRSA");
    }
}
