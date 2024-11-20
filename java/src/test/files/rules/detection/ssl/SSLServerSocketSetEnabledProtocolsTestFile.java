import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;

class SSLServerSocketSetEnabledProtocolsTestFile {

    void test() {
        try (SSLServerSocket socket = (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket()) {
            // Noncompliant@+2 {{(TLS) TLSv1.2}}
            // Noncompliant@+1 {{(TLS) TLSv1.3}}
            socket.setEnabledProtocols(new String[] { "TLSv1.2", "TLSv1.3"});
        } catch (IOException exception) {
            return;
        }
    }

}