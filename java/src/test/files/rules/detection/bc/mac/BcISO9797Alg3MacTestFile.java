import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class BcISO9797Alg3MacTestFile {

    public static byte[] calculateMac(byte[] key, byte[] iv, byte[] data) {
        BlockCipher cipher = new AESEngine(); // Noncompliant {{AES}}
        ISO9797Alg3Mac mac = new ISO9797Alg3Mac(cipher, 64, new ISO7816d4Padding());
        // Noncompliant@-1 {{ISO9797Alg3Mac}}

        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv);
        mac.init(keyParamWithIV);

        mac.update(data, 0, data.length);

        byte[] macResult = new byte[mac.getMacSize()];
        mac.doFinal(macResult, 0);

        return macResult;
    }
}
