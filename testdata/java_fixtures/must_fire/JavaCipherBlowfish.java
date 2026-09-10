package mustfire;

import javax.crypto.Cipher;

public class JavaCipherBlowfish {
    public Cipher legacy() throws Exception {
        return Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
    }
}
