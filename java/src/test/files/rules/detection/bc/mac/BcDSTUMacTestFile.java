import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.macs.DSTU7564Mac;
import org.bouncycastle.crypto.macs.DSTU7624Mac;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcDSTUMacTestFile {

    private static void test1() {
        // Generate a random key
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

        // Initialize DSTU7564Mac with the cipher and MAC size in bits
        int macSizeInBits = 128; // 128 bits = 16 bytes

        // Initialize DSTU7564Mac with the cipher
        DSTU7564Mac mac = new DSTU7564Mac(macSizeInBits); // Noncompliant {{(Mac) Kupyna}}

        // Compute MAC
        mac.init(new KeyParameter(key)); // Initialize MAC with the same key as the cipher

        // ...
    }

    private static void test2() {
        // Generate a random key
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

        // Initialize DSTU7624Mac with the cipher and MAC size in bits
        int macSizeInBits = 128; // 128 bits = 16 bytes

        // Initialize DSTU7624Mac with the cipher
        DSTU7624Mac mac = new DSTU7624Mac(macSizeInBits, 0); // Noncompliant {{(Mac) Kalyna}}

        // Compute MAC
        mac.init(new KeyParameter(key)); // Initialize MAC with the same key as the cipher

        // ...
    }
}
