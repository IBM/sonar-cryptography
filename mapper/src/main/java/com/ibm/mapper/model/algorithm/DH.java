package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;

public final class DH extends PublicKeyEncryption {
    private static final String NAME = "DH"; // DiffieHellman

    public DH(@NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
    }

    public DH(@Nonnull KeyLength keyLength,
               @Nonnull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(keyLength);
    }
}
