package mustfire;

import javax.crypto.Cipher;

public class JavaCipherRsa {
    public Cipher wrapper() throws Exception {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }
}
