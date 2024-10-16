import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.MGF1BytesGenerator;

public class BcMGF1BytesGeneratorTestFile {

    public static void main(String[] args) {

        Digest digest = new SHA256Digest();
        MGF1BytesGenerator mgfFunction = new MGF1BytesGenerator(digest);
        // Noncompliant@-1 {{(MaskGenerationFunction) MGF1}}

        // ...
    }
}
