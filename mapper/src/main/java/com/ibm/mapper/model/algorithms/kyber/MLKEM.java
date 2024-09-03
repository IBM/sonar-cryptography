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
package com.ibm.mapper.model.algorithms.kyber;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

public class MLKEM extends Algorithm implements KeyEncapsulationMechanism {
    // https://csrc.nist.gov/pubs/fips/203/final
    // This is the standardized version of Kyber

    private static final String NAME = "ML-KEM"; // Module-Lattice-Based Key-Encapsulation Mechanism

    /** Returns a name of the form "ML-KEM-XXX" where XXX is the parameter set identifer */
    @Override
    @Nonnull
    public String getName() {
        StringBuilder builtName = new StringBuilder(this.name);

        Optional<INode> parameterSetIdentifier = this.hasChildOfType(ParameterSetIdentifier.class);

        if (parameterSetIdentifier.isPresent()) {
            builtName.append("-").append(parameterSetIdentifier.get().asString());
        }

        return builtName.toString();
    }

    public MLKEM(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyEncapsulationMechanism.class, detectionLocation);
    }

    public MLKEM(int parameterSetIdentifier, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(
                new ParameterSetIdentifier(
                        String.valueOf(parameterSetIdentifier), detectionLocation));
    }
}