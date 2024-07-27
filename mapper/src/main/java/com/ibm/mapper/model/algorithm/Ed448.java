package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public class Ed448 extends Signature {
    private static final String NAME = "Ed448";

    public Ed448(@NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(new EllipticCurve("Curve448", detectionLocation));
        this.append(new SHAKE(
                new DigestSize(256, detectionLocation),
                detectionLocation
        ));
    }
}
