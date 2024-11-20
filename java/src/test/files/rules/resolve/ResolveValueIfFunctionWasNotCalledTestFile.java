package test.files.rules.java.resolve;

import javax.ws.rs.BadRequestException;
import java.security.*;
import java.security.spec.*;
import java.security.Key;
import javax.crypto.Cipher;

public class ResolveValueIfFunctionWasNotCalledTestFile {
    private static ECParameterSpec getECParameterSpec(String curveName) throws VertxException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC"); // Noncompliant {{(Key) EC}}
            keyPairGenerator.initialize(new ECGenParameterSpec(curveName));
            ECPublicKey publicKey = (ECPublicKey) keyPairGenerator.generateKeyPair().getPublic();
            return publicKey.getParams();
        } catch (GeneralSecurityException e) {
            throw new VertxException("Cannot determine EC parameter spec for com.ibm.enricher.curve name/OID", e);
        }
    }
}