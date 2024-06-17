import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.macs.Blake3Mac;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcBlake3MacTestFile {

    public static byte[] generateBlake3Mac(byte[] key, byte[] message) {
        Blake3Digest blake3Digest = new Blake3Digest();
        KeyParameter keyParameter = new KeyParameter(key);

        Mac blake3Mac = new Blake3Mac(blake3Digest); // Noncompliant {{Blake3Mac}}
        blake3Mac.init(keyParameter);

        blake3Mac.update(message, 0, message.length);
        byte[] output = new byte[blake3Mac.getMacSize()];
        blake3Mac.doFinal(output, 0);

        return output;
    }
}
