package test.files.rules.java.resolve;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ResolveFunctionCallBeforeAndAfterDefinitionTestFile {

    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    private static final String MERCHANT_KEY = "0123456789abcdef";

    public void genCipherBeforeDefinitionTest() {
        Cipher c = genCipher("RSA/ECB/PKCS1Padding", Cipher.ENCRYPT_MODE); // Noncompliant {{(PublicKeyEncryption) RSA-2048}}
    }

    public Cipher genCipher(String cipher, int mode) {
        Cipher c = Cipher.getInstance(cipher);
        SecretKey secretKey = new SecretKeySpec(MERCHANT_KEY.getBytes(), "AES"); // Noncompliant {{(SecretKey) AES}}
        c.init(mode, secretKey);
        return c;
    }

    public void genCipherAfterDefinitionTest() {
        Cipher c = genCipher("AES/ECB/PKCS5Padding", Cipher.DECRYPT_MODE); // Noncompliant {{(BlockCipher) AES128-ECB-PKCS5}}
    }

}