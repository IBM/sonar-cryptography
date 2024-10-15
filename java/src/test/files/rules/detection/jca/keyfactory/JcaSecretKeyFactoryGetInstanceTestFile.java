import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class JcaSecretKeyFactoryGetInstanceTestFile {
    public void des() throws InvalidKeyException {
        SecretKey secretKey = SecretKeyFactory.getInstance("DES"); // Noncompliant {{(SecretKey) DES}}
    }

}