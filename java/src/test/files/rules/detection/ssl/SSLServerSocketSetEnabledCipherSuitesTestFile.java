import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;

public class SSLServerSocketSetEnabledCipherSuitesTestFile {

    void test() {
        try (SSLServerSocket socket = (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket()) {
            // Noncompliant@+1 {{TLS_DHE_DSS_WITH_AES_256_CBC_SHA256}}
            socket.setEnabledCipherSuites(new String[] { "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" });
        } catch (IOException exception) {
            return;
        }
    }
}