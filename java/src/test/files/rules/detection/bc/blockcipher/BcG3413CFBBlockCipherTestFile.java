import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.G3413CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcG3413CFBBlockCipherTestFile {

    public void AESCipherCBCnoPad(byte[] key) {
        // TODO: This detection should optimally not happen once GOST3412_2015 has been detected as a child finding of G3413CFBBlockCipher
        GOST3412_2015Engine engine = new GOST3412_2015Engine(); //  Noncompliant {{GOST R 34.12-2015}}
        G3413CFBBlockCipher cipher = new G3413CFBBlockCipher(engine, 128); // Noncompliant {{GOST R 34.12-2015|CFB}}
        KeyParameter kp = new KeyParameter(key);
        cipher.init(true, kp);
        return;
    }
}