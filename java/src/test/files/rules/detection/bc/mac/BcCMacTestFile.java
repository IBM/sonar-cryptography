import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcCMacTestFile {
    public byte[] generateCMac(byte[] key, byte[] data) throws Exception {
        // Using AES engine with a 128-bit MAC size
        Mac mac = new CMac(new AESEngine(), 128); // Noncompliant {{CMac}}
        // Noncompliant@-1 {{AES}}

        CipherParameters params = new KeyParameter(key);
        mac.init(params);

        mac.update(data, 0, data.length);

        byte[] output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);

        return output;
    }
}
