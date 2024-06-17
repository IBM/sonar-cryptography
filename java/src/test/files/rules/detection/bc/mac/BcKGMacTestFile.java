import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.macs.KGMac;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class BcKGMacTestFile {
    public static void exampleGMAC() {
        byte[] key = Hex.decode("00112233445566778899AABBCCDDEEFF");
        byte[] input = Hex.decode("48656c6c6f20576f726c64"); // "Hello World" in hex

        DSTU7624Engine engine = new DSTU7624Engine(64); // Noncompliant {{DSTU 7624:2014}}
        KGCMBlockCipher blockCipher = new KGCMBlockCipher(engine); // Noncompliant {{KGCM}}
        KGMac gmac = new KGMac(blockCipher, 128); // Noncompliant {{KGMac}}

        CipherParameters params = new KeyParameter(key);
        gmac.init(params);

        gmac.update(input, 0, input.length);
        byte[] outputMac = new byte[gmac.getMacSize()];
        gmac.doFinal(outputMac, 0);

        System.out.println(Hex.toHexString(outputMac)); // Output the MAC in hex
    }
}
