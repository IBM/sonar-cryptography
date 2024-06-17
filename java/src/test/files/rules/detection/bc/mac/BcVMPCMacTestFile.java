import org.bouncycastle.crypto.macs.VMPCMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcVMPCMacTestFile {

    public static byte[] calculateMac(byte[] key, byte[] data) {
        VMPCMac vmpcMac = new VMPCMac(); // Noncompliant {{VMPCMac}}
        vmpcMac.init(new KeyParameter(key));
        vmpcMac.update(data, 0, data.length);
        byte[] mac = new byte[vmpcMac.getMacSize()];
        vmpcMac.doFinal(mac, 0);
        return mac;
    }
}
