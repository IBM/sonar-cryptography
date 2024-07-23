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

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaEllipticCurveMapper implements IMapper {
    private static final List<String> validValues =
            List.of("XDH", "EC", "EdDSA", "ECMQV", "ECDH", "X25519", "X448", "Ed25519", "Ed448");

    private static Optional<String> getCurve(final String str) {
        if (str == null) {
            return Optional.empty();
        }

        final String generalizedStr = str.toLowerCase().trim();
        return switch (generalizedStr) {
            case "x25519", "ed25519" -> Optional.of("curve25519");
            case "x448", "ed448" -> Optional.of("curve448");
            default -> Optional.empty();
        };
    }

    @Nonnull
    @Override
    public Optional<Algorithm> parse(
            @Nullable String str,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }

        if (!reflectValidValues(str)) {
            return Optional.empty();
        }

        JcaBaseAlgorithmMapper algorithmMapper = new JcaBaseAlgorithmMapper();
        Optional<Algorithm> algorithmOptional =
                algorithmMapper.parse(str, detectionLocation, configuration);
        if (algorithmOptional.isEmpty()) {
            return Optional.empty();
        }

        Algorithm algorithm = algorithmOptional.get();
        // get curve
        Optional<EllipticCurve> curve =
                getCurve(str)
                        .map(curveStr -> new EllipticCurve(curveStr, detectionLocation))
                        .map(
                                c -> {
                                    c.apply(configuration);
                                    return c;
                                });

        // create ec
        EllipticCurveAlgorithm ellipticCurveAlgorithm =
                curve.map(c -> new EllipticCurveAlgorithm(algorithm, c))
                        .orElseGet(() -> new EllipticCurveAlgorithm(algorithm));

        final String generalizedStr = str.toLowerCase().trim();
        return switch (generalizedStr) {
            case "ecdh", "ecmqv", "xdh", "x448", "x25519" ->
                    Optional.of(new KeyAgreement(ellipticCurveAlgorithm));
            default -> Optional.of(ellipticCurveAlgorithm);
        };
    }

    private boolean reflectValidValues(final @Nonnull String str) {
        return validValues.stream().anyMatch(str::equalsIgnoreCase);
    }
}
