package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;

public final class Poly1305 extends MessageDigest {
    private static final String NAME = "Poly1305";

    public Poly1305(
            @Nonnull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
    }
}
