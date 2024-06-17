import org.bouncycastle.crypto.macs.SipHash;
import org.bouncycastle.crypto.macs.SipHash128;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcSipHash128TestFile {
    public static long sipHash(byte[] data, byte[] key) {
        SipHash sipHash = new SipHash(); // Noncompliant {{SipHash}}
        sipHash.init(new KeyParameter(key));
        sipHash.update(data, 0, data.length);
        return sipHash.doFinal();
    }

    public static long sipHash128(byte[] data, byte[] key) {
        SipHash128 sipHash = new SipHash128(); // Noncompliant {{SipHash128}}
        sipHash.init(new KeyParameter(key));
        sipHash.update(data, 0, data.length);
        return sipHash.doFinal();
    }
}
