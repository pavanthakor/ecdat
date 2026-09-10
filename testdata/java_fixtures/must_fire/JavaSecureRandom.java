package mustfire;

import java.security.SecureRandom;

// A control: this is the correct choice and belongs in the inventory.
public class JavaSecureRandom {
    public byte[] nonce() {
        SecureRandom rng = new SecureRandom();
        byte[] buffer = new byte[16];
        rng.nextBytes(buffer);
        return buffer;
    }
}
