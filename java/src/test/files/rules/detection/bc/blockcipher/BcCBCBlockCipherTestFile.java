import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcCBCBlockCipherTestFile {
    public void AESCipherCBCnoPad1(byte[] key) {
        // This detection should optimally not happen once AES has been detected as a child finding of CBCBlockCipher
        org.bouncycastle.crypto.BlockCipher aes = new AESFastEngine(); //  Noncompliant {{(BlockCipher) AES}}
        CBCBlockCipher cbc = new CBCBlockCipher(aes); //  Noncompliant {{(BlockCipher) AES-CBC}}
        KeyParameter kp = new KeyParameter(key);
        cbc.init(true, kp);
        return;
    }

    public void AESCipherCBCnoPad2(byte[] key) {
        // This detection should optimally not happen once AES has been detected as a child finding of CBCBlockCipher
        org.bouncycastle.crypto.BlockCipher aes = AESEngine.newInstance(); //  Noncompliant {{(BlockCipher) AES}}
        CBCBlockCipher cbc = CBCBlockCipher.newInstance(aes); //  Noncompliant {{(BlockCipher) AES-CBC}}
        KeyParameter kp = new KeyParameter(key);
        cbc.init(false, kp);
        return;
    }
}