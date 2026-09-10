package mustfire;

public class JavaPemPrivateKey {
    // An embedded private key. Never a Finding's snippet.
    private static final String SIGNING_KEY =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "JAVANOTAREALKEYJAVANOTAREALKEYJAVANOTAREALKEYJAVANOTAREALKEY0000\n"
        + "-----END RSA PRIVATE KEY-----";

    public String key() {
        return SIGNING_KEY;
    }
}
