import javax.crypto.KeyAgreement;
import javax.crypto.ShortBufferException;
import java.security.NoSuchAlgorithmException;

public class JcaKeyAgreementGenerateSecretKeySizeTestFile {

    public void test() throws NoSuchAlgorithmException, ShortBufferException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");  // Noncompliant {{DiffieHellman}}
        keyAgreement.generateSecret(new byte[256], 0);
    }
}