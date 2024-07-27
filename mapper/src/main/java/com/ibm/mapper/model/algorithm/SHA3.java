package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;

public final class SHA3 extends MessageDigest {
    private static final String NAME = "SHA3";

    public SHA3(
            @Nonnull DigestSize digestSize,
            @Nonnull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(digestSize);
    }

    public SHA3(
            @Nonnull DigestSize digestSize,
            @Nonnull MessageDigest preHash,
            @Nonnull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(digestSize);
        this.append(preHash);
    }
}
