import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class JcaKeyAgreementGenerateSecretAlgorithmTestFile {

    public void test() throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");  // Noncompliant {{DiffieHellman}}
        keyAgreement.generateSecret("AES");
    }

}