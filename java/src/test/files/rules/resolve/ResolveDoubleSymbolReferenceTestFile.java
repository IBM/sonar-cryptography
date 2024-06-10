package test.files.rules.java.resolve;

import java.io.File;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ResolveDoubleSymbolReferenceTestFile {

    private static final String MERCHANT_KEY = "0123456789abcdef";

    public void cipher1() throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Noncompliant {{RSA/ECB/PKCS1Padding}}
        SecretKey secretKey = new SecretKeySpec(MERCHANT_KEY.getBytes(), "AES"); // Noncompliant {{AES}}
        c.init(Cipher.DECRYPT_MODE, secretKey);
        c.wrap(secretKey);
    }

}