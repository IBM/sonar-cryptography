import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;

public class JcaKeyFactoryGetInstanceTestFile {
    public void test() throws NoSuchAlgorithmException {
        KeyFactory factory = KeyFactory.getInstance("RSA"); // Noncompliant {{(Key) RSA}}
    }
}