package mustfire;

import javax.net.ssl.SSLContext;

public class JavaSslContext {
    public SSLContext legacy() throws Exception {
        return SSLContext.getInstance("TLSv1");
    }
}
