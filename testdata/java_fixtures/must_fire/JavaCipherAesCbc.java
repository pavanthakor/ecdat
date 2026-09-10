package mustfire;

import javax.crypto.Cipher;

public class JavaCipherAesCbc {
    public Cipher cbc() throws Exception {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }
}
