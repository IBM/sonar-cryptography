package test.files.rules.java.resolve;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class ResolveCallFromOtherClassTestFile {
    public static Key generate(String algo, int keySize) {
        SecretKey key = null;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
            keyGenerator.init(keySize);
            Key key = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            // nothing
        }
        return key;
    }
}

public class OtherClass {
    public void callCryptoFunction() {
        int keySize = 4096;
        Key test = ResolveCallFromOtherClassTestFile.generate("RSA", keySize);  // Noncompliant {{(SecretKey) RSA}}
    }

    public void callCryptoFunction2() {
        Key test = ResolveCallFromOtherClassTestFile.generate("AES", 128); // Noncompliant {{(SecretKey) AES}}
    }
}