import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;

public class Issue16TestFile {

    public static void test() {
        // Instantiate GCMBlockCipher with newInstance() method
        GCMBlockCipher newInstance =
                (GCMBlockCipher) GCMBlockCipher.newInstance(AESEngine.newInstance());  // Noncompliant {{(AuthenticatedEncryption) AES-GCM}} {{(BlockCipher) AES}}
    }

}