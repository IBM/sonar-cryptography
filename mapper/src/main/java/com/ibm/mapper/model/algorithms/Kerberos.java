package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class Kerberos extends KeyAgreement {
    private static final String NAME = "KRB";

    public Kerberos(@NotNull DetectionLocation detectionLocation) {
        super(new Protocol(NAME, detectionLocation));
    }

    public Kerberos(int version, @NotNull DetectionLocation detectionLocation) {
        super(new Protocol(NAME+version, detectionLocation));
    }
}
