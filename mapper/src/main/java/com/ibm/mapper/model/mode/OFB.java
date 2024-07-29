package com.ibm.mapper.model.mode;

import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class OFB extends Mode {

    /*
     * NOTE:
     * CFB/OFB with no specified value defaults to the block size of the algorithm.
     * (i.e. AES is 128; Blowfish, DES, DESede, and RC2 are 64.)
     */
    public OFB(@NotNull DetectionLocation detectionLocation) {
        super("OFB", detectionLocation);
    }

    public OFB(
            int s,
            @NotNull DetectionLocation detectionLocation) {
        super("OFB-" + s, detectionLocation);
    }
}
