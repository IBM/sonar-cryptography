package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;

public final class ECDH extends KeyAgreement {
    private static final String NAME = "ECDH"; // DiffieHellman

    public ECDH(@NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
    }

    public ECDH(@Nonnull EllipticCurve ellipticCurve,
              @Nonnull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(ellipticCurve);
    }

}
