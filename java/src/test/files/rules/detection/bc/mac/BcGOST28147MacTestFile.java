import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.macs.GOST28147Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class BcGOST28147MacTestFile {
    public static void main(String[] args) {
        try {
            byte[] key = Hex.decode("0123456789abcdef0123456789abcdef");
            byte[] input = "Hello, BouncyCastle!".getBytes();

            GOST28147Mac mac = new GOST28147Mac(); // Noncompliant {{GOST28147Mac}}
            CipherParameters params = new ParametersWithIV(new KeyParameter(key), new byte[10]);
            mac.init(params);

            mac.update(input, 0, input.length);
            byte[] output = new byte[mac.getMacSize()];
            mac.doFinal(output, 0);

            System.out.println("MAC: " + Hex.toHexString(output));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
