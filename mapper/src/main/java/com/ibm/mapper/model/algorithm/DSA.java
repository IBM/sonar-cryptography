package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class DSA extends Signature {
    private static final String NAME = "DSA";

    public DSA(@NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
    }
}
