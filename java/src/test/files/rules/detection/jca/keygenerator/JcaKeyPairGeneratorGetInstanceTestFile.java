import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
public class JcaKeyPairGeneratorGetInstanceTestFile {
    public void test() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); // Noncompliant {{(Key) RSA}}
    }

}