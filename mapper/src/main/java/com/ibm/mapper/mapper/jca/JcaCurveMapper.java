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
package com.ibm.mapper.mapper.jca;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.curves.Secp256r1;
import com.ibm.mapper.model.curves.Secp384r1;
import com.ibm.mapper.model.curves.Secp521r1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class JcaCurveMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends Algorithm> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "ED25519" -> Optional.of(new Ed25519(detectionLocation));
            case "ED448" -> Optional.of(new Ed448(detectionLocation));
            case "SECP256R1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Secp256r1(detectionLocation)));
            case "SECP384R1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Secp384r1(detectionLocation)));
            case "SECP521R1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Secp521r1(detectionLocation)));
            case "X25519" -> Optional.of(new X25519(detectionLocation));
            case "X448" -> Optional.of(new X448(detectionLocation));
            default -> Optional.empty();
        };
    }
}
