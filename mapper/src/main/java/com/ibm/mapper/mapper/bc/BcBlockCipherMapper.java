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
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcBlockCipherMapper implements IMapper {

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
            @Nonnull String cipherAlgorithm, @Nonnull DetectionLocation detectionLocation) {
        return switch (cipherAlgorithm) {
            case "AESEngine" -> Optional.of(new AES(detectionLocation));
            case "AESFastEngine" -> Optional.of(new AES(detectionLocation));
            case "AESLightEngine" -> Optional.of(new AES(detectionLocation));
            case "ARIAEngine" -> Optional.empty();
            case "BlowfishEngine" -> Optional.empty();
            case "CamelliaEngine" -> Optional.empty();
            case "CamelliaLightEngine" -> Optional.empty();
            case "CAST5Engine" -> Optional.empty();
            case "CAST6Engine" -> Optional.empty();
            case "DESedeEngine" -> Optional.empty();
            case "DESEngine" -> Optional.empty();
            case "DSTU7624Engine" -> Optional.empty();
            case "GOST28147Engine" -> Optional.empty();
            case "GOST3412_2015Engine" -> Optional.empty();
            case "IDEAEngine" -> Optional.empty();
            case "LEAEngine" -> Optional.empty();
            case "NoekeonEngine" -> Optional.empty();
            case "NullEngine" -> Optional.empty();
            case "RC2Engine" -> Optional.empty();
            case "RC532Engine" -> Optional.empty();
            case "RC564Engine" -> Optional.empty();
            case "RC6Engine" -> Optional.empty();
            case "RijndaelEngine" -> Optional.empty();
            case "SEEDEngine" -> Optional.empty();
            case "SerpentEngine" -> Optional.empty();
            case "Shacal2Engine" -> Optional.empty();
            case "SkipjackEngine" -> Optional.empty();
            case "SM4Engine" -> Optional.empty();
            case "TEAEngine" -> Optional.empty();
            case "ThreefishEngine" -> Optional.empty();
            case "TnepresEngine" -> Optional.empty();
            case "TwofishEngine" -> Optional.empty();
            case "XTEAEngine" -> Optional.empty();

            default -> {
                final Algorithm algorithm =
                        new Algorithm(cipherAlgorithm, Unknown.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
