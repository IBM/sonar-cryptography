package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public class Ed25519 extends Signature {
    private static final String NAME = "Ed25519";

    public Ed25519(@NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(new EllipticCurve("Curve25519", detectionLocation));
        this.append(new SHA2(
                new DigestSize(512, detectionLocation),
                detectionLocation
        ));
    }
}
