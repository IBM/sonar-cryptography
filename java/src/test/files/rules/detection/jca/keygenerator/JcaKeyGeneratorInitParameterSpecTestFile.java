import javax.crypto.KeyGenerator;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class JcaKeyGeneratorInitParameterSpecTestFile {

    public void generateKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES"); // Noncompliant {{(SecretKey) DES}}
    }

}