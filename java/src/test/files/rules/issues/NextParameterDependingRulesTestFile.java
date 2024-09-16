import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;

public class NextParameterDependingRulesTestFile {

    /* Does not work: AES is not set as a child of GCM */
    public GCMBlockCipher test1() {
        GCMBlockCipher blockCipher = GCMBlockCipher.newInstance(AESEngine.newInstance()); // Noncompliant {{GCMBlockCipher}}
        // Noncompliant@-1 {{AESEngine}}
        return blockCipher;
    }

    /* Works: AES is set as a child of GCM */
    public GCMBlockCipher test2() { 
        GCMBlockCipher blockCipher = new GCMBlockCipher(new AESEngine()); // Noncompliant {{GCMBlockCipher}}
        // Noncompliant@-1 {{AESEngine}}
        return blockCipher;
    }
}
