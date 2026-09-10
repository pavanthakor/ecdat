package mustfire;

import java.security.KeyPairGenerator;
import java.security.KeyPair;

public class JavaDsaKeygen {
    public KeyPair newDsaKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }
}
