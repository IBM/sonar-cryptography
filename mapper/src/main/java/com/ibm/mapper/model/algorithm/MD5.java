package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;

public final class MD5 extends MessageDigest {

    public MD5(@Nonnull DetectionLocation detectionLocation) {
        super(new Algorithm("MD5", detectionLocation));
    }
}
