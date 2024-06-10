import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
public class JcaDESedeKeySpecTestFile {
    public void test() throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede"); // Noncompliant {{DESede}}
        SecretKey secretKey = factory.generateSecret(new DESedeKeySpec(new byte[8]));
    }

}