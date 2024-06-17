import org.bouncycastle.crypto.macs.Zuc256Mac;

public class BcZuc256MacTestFile {
    public static void demonstrateZuc256Mac(int pLength) {
        Zuc256Mac zucMac = new Zuc256Mac(pLength); // Noncompliant {{Zuc256Mac}}
        // ...
    }
}
