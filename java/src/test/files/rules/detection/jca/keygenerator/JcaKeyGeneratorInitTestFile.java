import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class JcaKeyGeneratorInitTestFile {

    public void generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES"); // Noncompliant {{(SecretKey) AES}}
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();
    }

}