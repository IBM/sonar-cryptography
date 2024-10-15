import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class JcaCipherSecretKeySpecTestFile {

    private static final String MERCHANT_KEY = "0123456789abcdef0123456789abcdef";

    public void cipher() throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS1Padding"); // Noncompliant {{(BlockCipher) AES128-CBC-PKCS1}}
        SecretKey secretKey = new SecretKeySpec(MERCHANT_KEY.getBytes(), "AES"); // Noncompliant {{(SecretKey) AES}}
        c.init(Cipher.DECRYPT_MODE, secretKey);
    }

}