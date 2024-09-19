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
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class TupleHash extends Algorithm implements ExtendableOutputFunction {
    // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

    private static final String NAME = "TupleHash";

    public TupleHash(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, ExtendableOutputFunction.class, detectionLocation);
    }

    public TupleHash(int digestSize, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new DigestSize(digestSize, detectionLocation));
    }
}
