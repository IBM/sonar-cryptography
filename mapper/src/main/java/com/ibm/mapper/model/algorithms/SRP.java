package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

// Secure Remote Password protocol
public final class SRP extends KeyAgreement {
    private static final String NAME = "SRP";

    public SRP(@NotNull DetectionLocation detectionLocation) {
        super(new Protocol(NAME, detectionLocation));
    }
}
