package com.ibm.mapper.model.mode;

import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class CFB extends Mode {

    /*
     * NOTE:
     * CFB/OFB with no specified value defaults to the block size of the algorithm.
     * (i.e. AES is 128; Blowfish, DES, DESede, and RC2 are 64.)
     */
    public CFB(@NotNull DetectionLocation detectionLocation) {
        super("CFB", detectionLocation);
    }

    /*
     * NIST SP800-38A defines CFB with a bit-width.[28] The CFB mode also requires an integer
     * parameter, denoted s, such that 1 ≤ s ≤ b. In the specification of the CFB mode below,
     * each plaintext segment (Pj) and ciphertext segment (Cj) consists of s bits. The value
     * of s is sometimes incorporated into the name of the mode, e.g., the 1-bit CFB mode,
     * the 8-bit CFB mode, the 64-bit CFB mode, or the 128-bit CFB mode.
     */
    public CFB(
            int s,
            @NotNull DetectionLocation detectionLocation) {
        super("CFB" + s, detectionLocation);
    }
}
