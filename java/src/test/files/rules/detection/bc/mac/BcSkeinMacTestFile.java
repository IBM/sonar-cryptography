import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.SkeinMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class BcSkeinMacTestFile {

    public static void useSkeinMac() {
        // Initialize SkeinMac with state size and digest size
        int stateSizeBits = 128; // Example state size
        int digestSizeBits = 256; // Example digest size
        Mac skeinMac = new SkeinMac(stateSizeBits, digestSizeBits); // Noncompliant {{SkeinMac}}

        // Provide input data
        byte[] data = "Hello, Bouncy Castle!".getBytes();

        // Initialize the SkeinMac with a key
        byte[] key = "ThisIsASecretKey".getBytes();
        skeinMac.init(new KeyParameter(key));

        // Update the MAC with the data
        skeinMac.update(data, 0, data.length);

        // Calculate the MAC
        byte[] mac = new byte[skeinMac.getMacSize()];
        skeinMac.doFinal(mac, 0);

        // Print the MAC in hexadecimal format
        System.out.println("SkeinMac: " + Hex.toHexString(mac));
    }
}
