package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;

public final class RC5 extends BlockCipher {
    private static final String NAME = "RC5"; // ARC2

    public RC5(@NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
    }

    public RC5(@Nonnull DigestSize digestSize,
               @NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(digestSize);
    }

    public RC5(@Nonnull DigestSize digestSize,
               @Nonnull Mode mode,
               @NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(digestSize);
        this.append(mode);
    }

    public RC5(@Nonnull DigestSize digestSize,
               @Nonnull Mode mode,
               @Nonnull Padding padding,
               @NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(digestSize);
        this.append(mode);
        this.append(padding);
    }
}
