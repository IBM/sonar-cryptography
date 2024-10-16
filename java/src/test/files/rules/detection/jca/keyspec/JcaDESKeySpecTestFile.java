import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
public class JcaDESKeySpecTestFile {
    public void test() throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES"); // Noncompliant {{(SecretKey) DES}}
        SecretKey secretKey = factory.generateSecret(new DESKeySpec(new byte[8]));
    }

}