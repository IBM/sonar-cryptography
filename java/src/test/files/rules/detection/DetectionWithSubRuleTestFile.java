import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

public class DetectionWithSubRuleTestFile {

    void test(Cipher cipher) throws InvalidKeyException {
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec("0123456789ABCDEF".getBytes(), "AES")); // Noncompliant {{2}}
    }
}