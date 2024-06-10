import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
public class JcaKeyPairGeneratorInitializeTestFile {
    public void test() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); // Noncompliant {{RSA}}
        generator.initialize(1024);
    }
}