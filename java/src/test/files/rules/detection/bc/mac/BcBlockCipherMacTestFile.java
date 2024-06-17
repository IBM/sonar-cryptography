import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.BlockCipherMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcBlockCipherMacTestFile {

    public static byte[] generateBlockCipherMac(byte[] key, byte[] input) { 
        AESEngine cipher = new AESEngine(); // Noncompliant {{AES}}
        int macSizeInBits = 128;

        BlockCipherMac mac =
                new BlockCipherMac(cipher, macSizeInBits); // Noncompliant {{BlockCipherMac}}
        CipherParameters params = new KeyParameter(key);

        mac.init(params);

        mac.update(input, 0, input.length);

        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);

        return out;
    }
}
