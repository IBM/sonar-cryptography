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
import com.ibm.mapper.model.ClassicalBitSecurityLevel;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class KMAC extends Algorithm implements MessageDigest {
    // https://www.cryptosys.net/manapi/api_kmac.html

    private static final String NAME = "KMAC";

    /** Returns a name of the form "KMACXXX" where XXX is the security level in bits */
    @Override
    @Nonnull
    public String getName() {
        StringBuilder builtName = new StringBuilder(this.name);

        Optional<INode> bitSecurityLevel = this.hasChildOfType(ClassicalBitSecurityLevel.class);

        if (bitSecurityLevel.isPresent()) {
            builtName.append(bitSecurityLevel.get().asString());
        }

        return builtName.toString();
    }

    public KMAC(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, MessageDigest.class, detectionLocation);
    }

    public KMAC(int bitSecurityLevel, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new ClassicalBitSecurityLevel(bitSecurityLevel, detectionLocation));
        this.put(new DigestSize(2 * bitSecurityLevel, detectionLocation));
    }
}
