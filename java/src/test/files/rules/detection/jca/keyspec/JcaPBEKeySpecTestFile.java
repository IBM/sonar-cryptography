import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class JcaPBEKeySpecTestFile {

    public void test() throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); // Noncompliant {{(SecretKey) PBKDF2}}
        char[] password = "test".toCharArray();
        //byte[] salt = SecureRandom.getSeed(8);
        byte[] salt = "SecureRandom.getSeed(8);".getBytes();
        factory.generateSecret(new PBEKeySpec(password, salt, 2, 128));
    }

}