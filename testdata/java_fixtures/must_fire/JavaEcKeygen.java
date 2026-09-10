package mustfire;

import java.security.KeyPairGenerator;
import java.security.KeyPair;

public class JavaEcKeygen {
    public KeyPair newSigningKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }
}
