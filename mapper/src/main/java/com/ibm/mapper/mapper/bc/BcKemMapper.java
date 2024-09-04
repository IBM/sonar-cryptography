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
package com.ibm.mapper.mapper.bc;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.BIKE;
import com.ibm.mapper.model.algorithms.ClassicMcEliece;
import com.ibm.mapper.model.algorithms.ECIESKEM;
import com.ibm.mapper.model.algorithms.FrodoKEM;
import com.ibm.mapper.model.algorithms.HQC;
import com.ibm.mapper.model.algorithms.RSAKEM;
import com.ibm.mapper.model.algorithms.SABER;
import com.ibm.mapper.model.algorithms.kyber.Kyber;
import com.ibm.mapper.model.algorithms.ntru.NTRU;
import com.ibm.mapper.model.algorithms.ntru.NTRULPrime;
import com.ibm.mapper.model.algorithms.ntru.StreamlinedNTRUPrime;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcKemMapper implements IMapper {

    @Override
    @Nonnull
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        return map(str, detectionLocation);
    }

    @Nonnull
    private Optional<? extends INode> map(
            @Nonnull String kemString, @Nonnull DetectionLocation detectionLocation) {
        return switch (kemString) {
            case "BIKEKEMExtractor", "BIKEKEMGenerator" -> Optional.of(new BIKE(detectionLocation));
            case "CMCEKEMExtractor", "CMCEKEMGenerator" ->
                    Optional.of(new ClassicMcEliece(detectionLocation));
            case "ECIESKEMExtractor", "ECIESKEMGenerator" ->
                    Optional.of(new ECIESKEM(detectionLocation));
            case "FrodoKEMExtractor", "FrodoKEMGenerator" ->
                    Optional.of(new FrodoKEM(detectionLocation));
            case "HQCKEMExtractor", "HQCKEMGenerator" ->
                    Optional.of(new HQC(KeyEncapsulationMechanism.class, detectionLocation));
            case "KyberKEMExtractor", "KyberKEMGenerator" ->
                    Optional.of(new Kyber(detectionLocation));
            case "NTRUKEMExtractor", "NTRUKEMGenerator" -> Optional.of(new NTRU(detectionLocation));
            case "NTRULPRimeKEMExtractor", "NTRULPRimeKEMGenerator" ->
                    Optional.of(new NTRULPrime(detectionLocation));
            case "RSAKEMExtractor", "RSAKEMGenerator" -> Optional.of(new RSAKEM(detectionLocation));
            case "SABERKEMExtractor", "SABERKEMGenerator" ->
                    Optional.of(new SABER(detectionLocation));
            case "SNTRUPrimeKEMExtractor", "SNTRUPrimeKEMGenerator" ->
                    Optional.of(new StreamlinedNTRUPrime(detectionLocation));
            default -> {
                final Algorithm algorithm =
                        new Algorithm(
                                kemString, KeyEncapsulationMechanism.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
