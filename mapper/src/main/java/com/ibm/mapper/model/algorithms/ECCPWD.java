package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class ECCPWD extends KeyAgreement {
    private static final String NAME = "ECCPWD";

    public ECCPWD(@NotNull DetectionLocation detectionLocation) {
        super(new Protocol(NAME, detectionLocation));
    }
}
