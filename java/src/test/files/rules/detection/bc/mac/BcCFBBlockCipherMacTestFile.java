import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CFBBlockCipherMac;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class BcCFBBlockCipherMacTestFile {
    public static byte[] generateCFBMac(byte[] key, byte[] iv, byte[] data) throws Exception {
        BlockCipher cipher = new AESEngine(); // Noncompliant {{AES}}
        int cfbBitSize = 64;
        int macSizeInBits = 128;
        BlockCipherPadding padding = new PKCS7Padding();
        CFBBlockCipherMac mac =
                new CFBBlockCipherMac( // Noncompliant {{CFBBlockCipherMac}}
                        cipher,
                        cfbBitSize,
                        macSizeInBits,
                        padding);
        CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
        mac.init(params);
        mac.update(data, 0, data.length);
        byte[] macResult = new byte[mac.getMacSize()];
        mac.doFinal(macResult, 0);
        return macResult;
    }
}
