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
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public class SipHash extends Algorithm implements Mac {
    // https://en.wikipedia.org/wiki/SipHash

    private static final String NAME = "SipHash";

    public SipHash(int outputSize, @Nonnull DetectionLocation detectionLocation) {
        super(NAME, Mac.class, detectionLocation);
        this.put(new DigestSize(outputSize, detectionLocation));
        this.put(new KeyLength(128, detectionLocation));
    }

    public SipHash(@Nonnull DetectionLocation detectionLocation) {
        this(64, detectionLocation);
    }
}
