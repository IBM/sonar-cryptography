package test.files.rules.java.resolve;

import java.io.File;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;


public class ResolveMultipleDefinitionsForOneVariableTestFile {

    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    private static final String MERCHANT_KEY = "0123456789abcdef";

    /*
     * will detect four possible variants
     *  - aes-128-ecb with Cipher.DECRYPT_MODE
     *  - aes-128-ecb with Cipher.ENCRYPT_MODE
     *  - aes-128-cbc with Cipher.DECRYPT_MODE
     *  - aes-128-cbc with Cipher.ENCRYPT_MODE
     */
    public void cipherWithClause(byte[] message) {
        Cipher cipher;
        int mode;
        if ( message.length > 5 ) {
            // Noncompliant@+1 {{(BlockCipher) AES128-ECB-PKCS5}}
            cipher = Cipher.getInstance(TRANSFORMATION);
            mode = Cipher.DECRYPT_MODE;
        } else {
            // Noncompliant@+1 {{(BlockCipher) AES128-CBC}}
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
            mode = Cipher.ENCRYPT_MODE;
        }
        SecretKey secretKey = new SecretKeySpec(MERCHANT_KEY.getBytes(), "AES");  // Noncompliant {{(SecretKey) AES}}
        cipher.init(mode, secretKey);
    }

    public void callCipherWithClause() {
        cipherWithClause("testtest".getBytes());
    }
}