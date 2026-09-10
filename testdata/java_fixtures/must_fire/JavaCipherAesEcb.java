package mustfire;

import javax.crypto.Cipher;

public class JavaCipherAesEcb {
    // Named ECB outright.
    public Cipher ecb() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
