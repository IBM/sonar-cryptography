import org.bouncycastle.crypto.macs.KMAC;

public class BcKMACTestFile {
    public static void kmacExample() {
        byte[] key = "secretkey".getBytes();
        byte[] data = "hello".getBytes();

        KMAC kmac = new KMAC(256, key); // Noncompliant {{KMAC}}

        kmac.update(data, 0, data.length);
        byte[] output = new byte[32]; // 256 bits = 32 bytes
        kmac.doFinal(output, 0);
        System.out.println("KMAC output: " + new String(output));
    }
}
