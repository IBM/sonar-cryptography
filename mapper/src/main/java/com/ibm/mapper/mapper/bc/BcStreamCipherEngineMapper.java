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
import com.ibm.mapper.model.NonceLength;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.ChaCha20;
import com.ibm.mapper.model.algorithms.HC;
import com.ibm.mapper.model.algorithms.ISAAC;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.Salsa20;
import com.ibm.mapper.model.algorithms.ZUC;
import com.ibm.mapper.model.algorithms.grain.Grain128;
import com.ibm.mapper.model.algorithms.grain.Grainv1;
import com.ibm.mapper.model.algorithms.vmpc.VMPC;
import com.ibm.mapper.model.algorithms.vmpc.VMPCKSA;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcStreamCipherEngineMapper implements IMapper {

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
            @Nonnull String streamCipherString, @Nonnull DetectionLocation detectionLocation) {
        return switch (streamCipherString) {
            case "ChaCha7539Engine" -> Optional.of(new ChaCha20(detectionLocation));
            case "ChaChaEngine" -> Optional.of(new ChaCha20(detectionLocation));
            case "Grain128Engine" -> Optional.of(new Grain128(detectionLocation));
            case "Grainv1Engine" -> Optional.of(new Grainv1(detectionLocation));
            case "HC128Engine" -> Optional.of(new HC(128, detectionLocation));
            case "HC256Engine" -> Optional.of(new HC(256, detectionLocation));
            case "ISAACEngine" -> Optional.of(new ISAAC(detectionLocation));
            case "RC4Engine" -> Optional.of(new RC4(detectionLocation));
            case "Salsa20Engine" -> Optional.of(new Salsa20(detectionLocation));
            case "VMPCEngine" -> Optional.of(new VMPC(detectionLocation));
            case "VMPCKSA3Engine" -> Optional.of(new VMPCKSA(3, detectionLocation));
            case "XSalsa20Engine" -> {
                Salsa20 salsa20 = new Salsa20(256, detectionLocation);
                salsa20.put(new NonceLength(192, detectionLocation));
                yield Optional.of(salsa20);
            }
            case "Zuc128Engine" -> Optional.of(new ZUC(128, detectionLocation));
            case "Zuc256Engine" -> Optional.of(new ZUC(256, detectionLocation));
            default -> {
                final Algorithm algorithm =
                        new Algorithm(streamCipherString, StreamCipher.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
