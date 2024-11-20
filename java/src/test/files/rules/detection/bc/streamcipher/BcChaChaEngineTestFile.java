import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class BcChaChaEngineTestFile {
    public static void main(String[] args) {
        // Sample key
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");

        // Initialize the ChaCha engine with the provided key
        ChaChaEngine chachaEngine = new ChaChaEngine(); //  Noncompliant {{(StreamCipher) ChaCha20}}
        chachaEngine.init(true, new KeyParameter(key));
    }
}
