import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class JcaGCMParameterSpecTestFile {

    public void test() {
        String password = "password";
        String salt = "salt";

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // Noncompliant {{(SecretKey) PBKDF2}}
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES"); // Noncompliant {{(SecretKey) AES}}

        String nonce = "nonce";

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, Base64.getDecoder().decode(nonce));
        Cipher cipher = Cipher.getInstance("AES"); // Noncompliant {{(AuthenticatedEncryption) AES128-GCM}}
        cipher.init(Cipher.DECRYPT_MODE, secret, gcmSpec);
    }
}