import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcPoly1305TestFile {
    private static void test1() {
        // Generate a random key
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

        // Initialize AES cipher
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        // Initialize Poly1305 with the block cipher
        Poly1305 poly1305 = new Poly1305(aesEngine); // Noncompliant {{(Mac) Poly1305}}

        // Compute MAC
        poly1305.init(new KeyParameter(key)); // Initialize MAC with the same key as the cipher

        // ...
    }

    private static void test2() {
        // Generate a random key
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

        // Initialize Poly1305 with the block cipher
        Poly1305 poly1305 = new Poly1305(); // Noncompliant {{(Mac) Poly1305}}

        // Compute MAC
        poly1305.init(new KeyParameter(key)); // Initialize MAC with the same key as the cipher

        // ...
    }
}
