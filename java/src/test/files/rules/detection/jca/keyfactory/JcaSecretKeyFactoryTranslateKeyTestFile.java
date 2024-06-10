import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class JcaSecretKeyFactoryTranslateKeyTestFile {

    public void des() throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES"); // Noncompliant {{DES}}
        byte[] newKeyBytes = new byte[16];
        SecretKeySpec newSpec = new SecretKeySpec(newKeyBytes, "DESede"); // Noncompliant {{DESede}}
        SecretKey secretKey = factory.translateKey(newSpec);
    }

}