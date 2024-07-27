package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public class EdDSA extends Signature {
    private static final String NAME = "EdDSA";

    public EdDSA(@NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
    }
}
