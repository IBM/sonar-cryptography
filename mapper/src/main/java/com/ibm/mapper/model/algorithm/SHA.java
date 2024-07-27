package com.ibm.mapper.model.algorithm;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;

public final class SHA extends MessageDigest {

    public SHA(@Nonnull DetectionLocation detectionLocation) {
        super(new Algorithm("SHA1", detectionLocation));
    }
}
