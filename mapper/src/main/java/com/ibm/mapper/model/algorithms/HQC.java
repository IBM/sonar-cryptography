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
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public class HQC extends Algorithm implements KeyEncapsulationMechanism, PublicKeyEncryption {
    // https://pqc-hqc.org/doc/hqc-specification_2023-04-30.pdf

    private static final String NAME = "HQC"; // Hamming Quasi-Cyclic

    /** Returns a more specific name "HQC.KEM" or "HQC.PKE" length */
    @Override
    @Nonnull
    public String getName() {
        StringBuilder builtName = new StringBuilder(this.name);

        if (this.getKind() == KeyEncapsulationMechanism.class) {
            builtName.append(".KEM");
        } else if (this.getKind() == PublicKeyEncryption.class) {
            builtName.append(".PKE");
        }

        return builtName.toString();
    }

    // public HQC(@Nonnull DetectionLocation detectionLocation) {
    //     this(KeyEncapsulationMechanism.class, detectionLocation);
    // }

    public HQC(
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull DetectionLocation detectionLocation) {
        super(NAME, asKind, detectionLocation);
    }
}
