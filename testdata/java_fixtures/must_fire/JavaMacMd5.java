package mustfire;

import javax.crypto.Mac;

public class JavaMacMd5 {
    public Mac mac() throws Exception {
        return Mac.getInstance("HmacMD5");
    }
}
