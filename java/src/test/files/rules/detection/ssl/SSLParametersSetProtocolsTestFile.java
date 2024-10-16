import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;

public class SSLParametersSetProtocolsTestFile {

    void test() {
        try (SSLServerSocket socket = (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket()) {
            SSLParameters params = new SSLParameters();
            // Noncompliant@+2 {{(TLS) TLSv1.3}}
            // Noncompliant@+1 {{(TLS) TLSv1.2}}
            params.setProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
            socket.setSSLParameters(params);
        } catch (IOException exception) {
            return;
        }
    }
}