package mustfire;

import javax.crypto.Mac;

public class JavaMacSha1 {
    public Mac mac() throws Exception {
        return Mac.getInstance("HmacSHA1");
    }
}
