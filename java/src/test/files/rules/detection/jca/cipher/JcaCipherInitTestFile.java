import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class JcaCipherInitTestFile {
    public void cipher1() throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Noncompliant {{(PublicKeyEncryption) RSA-2048}}
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(MERCHANT_KEY.getBytes(), "AES"));
    }

}