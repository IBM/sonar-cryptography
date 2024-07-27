package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;

public final class SHAKE extends MessageDigest {
    private static final String NAME = "SHAKE";

    public SHAKE(
            @Nonnull DigestSize digestSize,
            @Nonnull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(digestSize);
    }
}
