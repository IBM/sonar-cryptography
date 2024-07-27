package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;

public final class DSA extends PublicKeyEncryption {
    private static final String NAME = "DSA";

    public DSA(@NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
    }

    public DSA(@Nonnull KeyLength keyLength,
               @Nonnull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(keyLength);
    }
}
