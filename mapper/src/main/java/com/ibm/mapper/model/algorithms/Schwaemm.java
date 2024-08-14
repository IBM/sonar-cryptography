/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2024 IBM
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.ClassicalBitSecurityLevel;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public class Schwaemm extends Algorithm implements AuthenticatedEncryption {
    private static final String NAME = "Schwaemm";

    public Schwaemm(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, AuthenticatedEncryption.class, detectionLocation);
    }

    private Schwaemm(@Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        super(name, AuthenticatedEncryption.class, detectionLocation);
    }

    public Schwaemm(int rate, @Nonnull DetectionLocation detectionLocation) {
        this(NAME + rate, detectionLocation);
    }

    public Schwaemm(int rate, int capacity, @Nonnull DetectionLocation detectionLocation) {
        this(NAME + rate + "-" + capacity, detectionLocation);
        this.put(new KeyLength(capacity, detectionLocation));
        this.put(new TagLength(capacity, detectionLocation));
        this.put(new ClassicalBitSecurityLevel(capacity - 8, detectionLocation));
    }
}
