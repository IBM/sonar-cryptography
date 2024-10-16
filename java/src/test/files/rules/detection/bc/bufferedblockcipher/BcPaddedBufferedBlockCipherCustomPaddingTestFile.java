import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class BcPaddedBufferedBlockCipherCustomPaddingTestFile {

    public static void test1() {
        
        CBCBlockCipher blockCipher = CBCBlockCipher.newInstance(AESEngine.newInstance()); // Noncompliant {{(BlockCipher) AES-CBC}}
        
        // Wrap the block cipher with PaddedBufferedBlockCipher
        PaddedBufferedBlockCipher paddedBlockCipher = new PaddedBufferedBlockCipher(blockCipher); // Noncompliant {{PaddedBuffered(PKCS7)}}
        
        // Initialize the PaddedBufferedBlockCipher with the parameters
        ParametersWithIV parametersWithIV = new ParametersWithIV(null, null);
        paddedBlockCipher.init(true, parametersWithIV); // true for encryption, false for decryption
    }
}
