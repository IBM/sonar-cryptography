import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class JcaKeyGeneratorGetInstanceTestFile {

    public void generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES"); // Noncompliant {{(SecretKey) AES}}
    }

}