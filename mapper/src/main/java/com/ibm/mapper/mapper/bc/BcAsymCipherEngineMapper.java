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
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.ElGamal;
import com.ibm.mapper.model.algorithms.NaccacheStern;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.ies.IES;
import com.ibm.mapper.model.algorithms.ntru.NTRUEncrypt;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcAsymCipherEngineMapper implements IMapper {

    private final Class<? extends IPrimitive> asKind;

    public BcAsymCipherEngineMapper(Class<? extends IPrimitive> asKind) {
        this.asKind = asKind;
    }

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
            @Nonnull String cipherString, @Nonnull DetectionLocation detectionLocation) {
        return switch (cipherString) {
            /* From asymmetricblockcipher.BcAsymCipherEngine */
            case "ElGamalEngine" ->
                    Optional.of(new ElGamal(asKind, new ElGamal(detectionLocation)));
            case "NaccacheSternEngine" ->
                    Optional.of(new NaccacheStern(asKind, new NaccacheStern(detectionLocation)));
            case "NTRUEngine" ->
                    Optional.of(new NTRUEncrypt(asKind, new NTRUEncrypt(detectionLocation)));
            case "RSABlindedEngine" -> Optional.of(new RSA(asKind, new RSA(detectionLocation)));
            case "RSABlindingEngine" -> Optional.of(new RSA(asKind, new RSA(detectionLocation)));
            case "RSAEngine" -> Optional.of(new RSA(asKind, new RSA(detectionLocation)));
            /* From other.BcIESEngine */
            case "IESEngine" -> Optional.of(new IES(asKind, new IES(detectionLocation)));
            /* From other.BcSM2Engine */
            case "SM2Engine" -> Optional.of(new SM2(asKind, new SM2(detectionLocation)));
            default -> {
                final Algorithm algorithm = new Algorithm(cipherString, asKind, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
