import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class JcaSecretKeyFactoryGenerateSecretTestFile {

    public void des() throws InvalidKeyException {
        byte[] keyBytes = new byte[8];
        DESKeySpec dkey = new DESKeySpec(keyBytes);
        SecretKey secretKey = SecretKeyFactory.getInstance("DES").generateSecret(dkey); // Noncompliant {{(SecretKey) DES}}
    }

}