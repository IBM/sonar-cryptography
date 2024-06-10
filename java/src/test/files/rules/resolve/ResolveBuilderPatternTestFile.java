package test.files.rules.java.resolve;

import javax.ws.rs.BadRequestException;
import java.security.*;
import java.security.spec.*;

public class ResolveBuilderPatternTestFile {

    private static final String DEFAULT_MESSAGE_DIGEST = "SHA-256";

    public static String createKeyId(Key key) {
        try {
            return MessageDigest.getInstance(DEFAULT_MESSAGE_DIGEST).digest(key.getEncoded()); // Noncompliant {{sha-256}}
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}