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
import com.ibm.mapper.model.algorithms.FrodoKEM;
import com.ibm.mapper.model.algorithms.HQC;
import com.ibm.mapper.model.algorithms.RSAKEM;
import com.ibm.mapper.model.algorithms.SABER;
import com.ibm.mapper.model.algorithms.ies.ECIESKEM;
import com.ibm.mapper.model.algorithms.kyber.Kyber;
import com.ibm.mapper.model.algorithms.ntru.NTRU;
import com.ibm.mapper.model.algorithms.ntru.NTRULPrime;
import com.ibm.mapper.model.algorithms.ntru.StreamlinedNTRUPrime;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Encapsulate;
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
            case "BIKEKEMExtractor" -> {
                var bike = new BIKE(detectionLocation);
                bike.put(new Decapsulate(detectionLocation));
                yield Optional.of(bike);
            }
            case "BIKEKEMGenerator" -> {
                var bike = new BIKE(detectionLocation);
                bike.put(new Encapsulate(detectionLocation));
                yield Optional.of(bike);
            }
            case "CMCEKEMExtractor" -> {
                var cmce = new ClassicMcEliece(detectionLocation);
                cmce.put(new Decapsulate(detectionLocation));
                yield Optional.of(cmce);
            }
            case "CMCEKEMGenerator" -> {
                var cmce = new ClassicMcEliece(detectionLocation);
                cmce.put(new Encapsulate(detectionLocation));
                yield Optional.of(cmce);
            }
            case "ECIESKEMExtractor" -> {
                var ecies = new ECIESKEM(detectionLocation);
                ecies.put(new Decapsulate(detectionLocation));
                yield Optional.of(ecies);
            }
            case "ECIESKEMGenerator" -> {
                var ecies = new ECIESKEM(detectionLocation);
                ecies.put(new Encapsulate(detectionLocation));
                yield Optional.of(ecies);
            }
            case "FrodoKEMExtractor" -> {
                var frodo = new FrodoKEM(detectionLocation);
                frodo.put(new Decapsulate(detectionLocation));
                yield Optional.of(frodo);
            }
            case "FrodoKEMGenerator" -> {
                var frodo = new FrodoKEM(detectionLocation);
                frodo.put(new Encapsulate(detectionLocation));
                yield Optional.of(frodo);
            }
            case "HQCKEMExtractor" -> {
                var hqc = new HQC(KeyEncapsulationMechanism.class, detectionLocation);
                hqc.put(new Decapsulate(detectionLocation));
                yield Optional.of(hqc);
            }
            case "HQCKEMGenerator" -> {
                var hqc = new HQC(KeyEncapsulationMechanism.class, detectionLocation);
                hqc.put(new Encapsulate(detectionLocation));
                yield Optional.of(hqc);
            }
            case "KyberKEMExtractor" -> {
                var kyber = new Kyber(detectionLocation);
                kyber.put(new Decapsulate(detectionLocation));
                yield Optional.of(kyber);
            }
            case "KyberKEMGenerator" -> {
                var kyber = new Kyber(detectionLocation);
                kyber.put(new Encapsulate(detectionLocation));
                yield Optional.of(kyber);
            }
            case "NTRUKEMExtractor" -> {
                var ntru = new NTRU(detectionLocation);
                ntru.put(new Decapsulate(detectionLocation));
                yield Optional.of(ntru);
            }
            case "NTRUKEMGenerator" -> {
                var ntru = new NTRU(detectionLocation);
                ntru.put(new Encapsulate(detectionLocation));
                yield Optional.of(ntru);
            }
            case "NTRULPRimeKEMExtractor" -> {
                var ntruLP = new NTRULPrime(detectionLocation);
                ntruLP.put(new Decapsulate(detectionLocation));
                yield Optional.of(ntruLP);
            }
            case "NTRULPRimeKEMGenerator" -> {
                var ntruLP = new NTRULPrime(detectionLocation);
                ntruLP.put(new Encapsulate(detectionLocation));
                yield Optional.of(ntruLP);
            }
            case "RSAKEMExtractor" -> {
                var rsa = new RSAKEM(detectionLocation);
                rsa.put(new Decapsulate(detectionLocation));
                yield Optional.of(rsa);
            }
            case "RSAKEMGenerator" -> {
                var rsa = new RSAKEM(detectionLocation);
                rsa.put(new Encapsulate(detectionLocation));
                yield Optional.of(rsa);
            }
            case "SABERKEMExtractor" -> {
                var saber = new SABER(detectionLocation);
                saber.put(new Decapsulate(detectionLocation));
                yield Optional.of(saber);
            }
            case "SABERKEMGenerator" -> {
                var saber = new SABER(detectionLocation);
                saber.put(new Encapsulate(detectionLocation));
                yield Optional.of(saber);
            }
            case "SNTRUPrimeKEMExtractor" -> {
                var sntruPrime = new StreamlinedNTRUPrime(detectionLocation);
                sntruPrime.put(new Decapsulate(detectionLocation));
                yield Optional.of(sntruPrime);
            }
            case "SNTRUPrimeKEMGenerator" -> {
                var sntruPrime = new StreamlinedNTRUPrime(detectionLocation);
                sntruPrime.put(new Encapsulate(detectionLocation));
                yield Optional.of(sntruPrime);
            }
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
