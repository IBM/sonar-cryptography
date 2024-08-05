package com.ibm.mapper.model;

import javax.annotation.Nonnull;

public class EllipticCurveAlgorithm extends Algorithm implements PublicKeyEncryption, Signature, KeyAgreement {

    public EllipticCurveAlgorithm(@Nonnull EllipticCurve curve) {
        super("EC-" + curve, PublicKeyEncryption.class, curve.detectionLocation);
        this.append(curve);
    }
}
