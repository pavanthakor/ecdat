package mustfire;

import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;

public class JavaBouncyCastleEc {
    public ECNamedCurveParameterSpec spec() {
        return ECNamedCurveTable.getParameterSpec("secp256r1");
    }
}
