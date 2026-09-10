package mustfire;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class JavaHardcodedKey {
    // A hard-coded AES key and IV. The sentinels below must reach NO Finding:
    // tests/test_rules_java.py asserts the redaction guard holds, INCLUDING
    // the cross-rule case -- the Cipher rule matches this file too.
    private static final String SECRET_KEY = "JAVASECRETSENTINEL0123456789abcd";

    private static final String STATIC_IV = "JAVANOTAREALKEY1";

    public Cipher encrypt() throws Exception {
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes("UTF-8"), "AES");
        IvParameterSpec iv = new IvParameterSpec(STATIC_IV.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher;
    }
}
