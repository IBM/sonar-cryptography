import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables8kGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcGCMBlockCipherTestFile {

    public static void test1() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);

        // Create a block cipher engine
        BlockCipher aesEngine = new AESFastEngine(); // Noncompliant {{AESFastEngine}}

        // Instantiate GCMBlockCipher with constructor
        GCMBlockCipher constructor = new GCMBlockCipher(aesEngine); // Noncompliant {{GCMBlockCipher}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        constructor.init(true, parameters); // true for encryption, false for decryption
    }

    public static void test2() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);

        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{AESEngine}}

        // Instantiate GCMBlockCipher with newInstance() method
        GCMBlockCipher newInstance =
                (GCMBlockCipher) GCMBlockCipher.newInstance(aesEngine); // Noncompliant {{GCMBlockCipher}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        newInstance.init(true, parameters); // true for encryption, false for decryption
    }

    public static void test3() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);

        // Create a block cipher engine
        BlockCipher aesEngine = new AESFastEngine(); // Noncompliant {{AESFastEngine}}

        // Create a GCMMultiplier (e.g., Tables8kGCMMultiplier)
        GCMMultiplier multiplier = new Tables8kGCMMultiplier();

        // Instantiate GCMBlockCipher with constructor
        GCMBlockCipher constructor = new GCMBlockCipher(aesEngine, multiplier); // Noncompliant {{GCMBlockCipher}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        constructor.init(true, parameters); // true for encryption, false for decryption
    }

    public static void test4() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);

        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{AESEngine}}

        // Create a GCMMultiplier (e.g., Tables8kGCMMultiplier)
        GCMMultiplier multiplier = new Tables8kGCMMultiplier();

        // Instantiate GCMBlockCipher with newInstance() method
        GCMBlockCipher newInstance =
                (GCMBlockCipher) GCMBlockCipher.newInstance(aesEngine, multiplier); // Noncompliant {{GCMBlockCipher}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        newInstance.init(true, parameters); // true for encryption, false for decryption
    }
}

