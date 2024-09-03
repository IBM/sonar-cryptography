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
import com.ibm.mapper.model.Version;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

public class Kyber extends Algorithm implements KeyEncapsulationMechanism {
    // https://pq-crystals.org/kyber/resources.shtml (details the multiple versions)
    // https://en.wikipedia.org/wiki/Kyber

    private static final String NAME = "Kyber"; // this is *not* ML-KEM

    /**
     * Returns a name of the form "Kyber-XXX (version YYY)" where XXX is the parameter set identifer
     * and YYY the submission version
     */
    @Override
    @Nonnull
    public String getName() {
        StringBuilder builtName = new StringBuilder(this.name);

        Optional<INode> parameterSetIdentifier = this.hasChildOfType(ParameterSetIdentifier.class);
        Optional<INode> version = this.hasChildOfType(Version.class);

        if (parameterSetIdentifier.isPresent()) {
            builtName.append("-").append(parameterSetIdentifier.get().asString());
        }
        if (version.isPresent()) {
            builtName.append(" (version ").append(version.get().asString()).append(")");
        }

        return builtName.toString();
    }

    public Kyber(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyEncapsulationMechanism.class, detectionLocation);
    }

    public Kyber(int parameterSetIdentifier, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(
                new ParameterSetIdentifier(
                        String.valueOf(parameterSetIdentifier), detectionLocation));
    }

    public Kyber(
            @Nonnull String submissionVersionNumber, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new Version(submissionVersionNumber, detectionLocation));
    }

    public Kyber(
            int parameterSetIdentifier,
            @Nonnull String submissionVersionNumber,
            @Nonnull DetectionLocation detectionLocation) {
        this(parameterSetIdentifier, detectionLocation);
        this.put(new Version(submissionVersionNumber, detectionLocation));
    }
}