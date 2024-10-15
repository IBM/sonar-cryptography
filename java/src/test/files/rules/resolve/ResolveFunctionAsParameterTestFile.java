import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class ResolveFunctionAsParameterTestFile {

    public void test() throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm());
    }

    public String algorithm() {
        return "RSA";  // Noncompliant {{(SecretKey) RSA}}
    }
}