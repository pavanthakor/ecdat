// Java call sites whose API names the usage (ADR-0030).
package usagesites;

import javax.crypto.Cipher;

public class UsageSites {
    // WRAP_MODE is KEY TRANSPORT, not bulk encryption -- and the mode is the
    // only thing that says so, since the transformation string is identical.
    public Cipher wrap() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.WRAP_MODE, (java.security.Key) null);
        return cipher;
    }
}
