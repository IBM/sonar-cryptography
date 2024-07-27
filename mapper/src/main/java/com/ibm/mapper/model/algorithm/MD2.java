package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;

public final class MD2 extends MessageDigest {

    public MD2(@Nonnull DetectionLocation detectionLocation) {
        super(new Algorithm("MD2", detectionLocation));
    }
}
