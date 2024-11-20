import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.params.CCMParameters;

public class BcCBCBlockCipherMacTestFile {
    public static void test1() {
        // Generate a random key and IV
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        byte[] iv = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

        // Initialize AES cipher with CBC mode
        BlockCipher cipher = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(true, params); // true for encryption, false for decryption

        // Initialize CBCBlockCipherMac with the cipher
        CBCBlockCipherMac mac = new CBCBlockCipherMac(cipher); // Noncompliant {{(Mac) AES}}

        // CipherParameter
        CCMParameters parameters = new CCMParameters(new KeyParameter(key), 128, new byte[12], new byte[12]);

        // Compute MAC
        mac.init(parameters); // Initialize MAC with the same key as the cipher

        // ...
    }

    public static void test2() {
        // Generate a random key and IV
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        byte[] iv = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

        // Initialize AES cipher with CBC mode
        BlockCipher cipher = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(true, params); // true for encryption, false for decryption

        // Padding scheme
        BlockCipherPadding padding = new PKCS7Padding();

        // Initialize CBCBlockCipherMac with the cipher
        CBCBlockCipherMac mac = new CBCBlockCipherMac(cipher, padding); // Noncompliant {{(Mac) AES}}

        // Compute MAC
        mac.init(new KeyParameter(key)); // Initialize MAC with the same key as the cipher

        // ...
    }

    public static void test3() {
        // Generate a random key and IV
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        byte[] iv = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

        // Initialize AES cipher with CBC mode
        BlockCipher cipher = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(true, params); // true for encryption, false for decryption

        // Initialize CBCBlockCipherMac with the cipher and MAC size in bits
        int macSizeInBits = 128; // 128 bits = 16 bytes

        // Initialize CBCBlockCipherMac with the cipher
        CBCBlockCipherMac mac = new CBCBlockCipherMac(cipher, macSizeInBits); // Noncompliant {{(Mac) AES}}

        // Compute MAC
        mac.init(new KeyParameter(key)); // Initialize MAC with the same key as the cipher

        // ...
    }

    public static void test4() {
        // Generate a random key and IV
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        byte[] iv = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

        // Initialize AES cipher with CBC mode
        BlockCipher cipher = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(true, params); // true for encryption, false for decryption

        // Initialize CBCBlockCipherMac with the cipher and MAC size in bits
        int macSizeInBits = 128; // 128 bits = 16 bytes

        // Padding scheme
        BlockCipherPadding padding = new PKCS7Padding();

        // Initialize CBCBlockCipherMac with the cipher
        CBCBlockCipherMac mac = new CBCBlockCipherMac(cipher, macSizeInBits, padding); // Noncompliant {{(Mac) AES}}

        // Compute MAC
        mac.init(new KeyParameter(key)); // Initialize MAC with the same key as the cipher

        // ...
    }
}
