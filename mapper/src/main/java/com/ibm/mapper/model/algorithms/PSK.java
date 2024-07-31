package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

// Pre-shared keys
public final class PSK extends KeyAgreement {
    private static final String NAME = "PSK";

    public PSK(@NotNull DetectionLocation detectionLocation) {
        super(new Protocol(NAME, detectionLocation));
    }
}
