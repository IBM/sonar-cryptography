import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SSLContextGetInstanceTestFile {

    void test() throws KeyManagementException, NoSuchAlgorithmException {
        // Noncompliant@+1 {{(TLS) TLSv1.2}}
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
    }

}