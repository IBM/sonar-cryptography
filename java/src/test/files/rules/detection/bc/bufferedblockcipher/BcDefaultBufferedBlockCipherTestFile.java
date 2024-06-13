import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class BcDefaultBufferedBlockCipherTestFile {

    public static void test1() {
        // Create a block cipher (AES in this case)
        BlockCipher cipher = AESEngine.newInstance(); // Noncompliant {{AES}}

        // Initialize the cipher with the key
        byte[] keyData = "0123456789abcdef".getBytes(StandardCharsets.UTF_8); // 128-bit key
        KeyParameter key = new KeyParameter(keyData);

        // Set up the initialization vector (IV)
        byte[] ivData = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8); // 128-bit IV
        ParametersWithIV parametersWithIV = new ParametersWithIV(key, ivData);

        // Wrap the block cipher with DefaultBufferedBlockCipher
        DefaultBufferedBlockCipher bufferedCipher = new DefaultBufferedBlockCipher(cipher); // Noncompliant {{DefaultBuffered}}

        // Initialize the DefaultBufferedBlockCipher with the parameters
        bufferedCipher.init(true, parametersWithIV); // true for encryption, false for decryption
    }
}
