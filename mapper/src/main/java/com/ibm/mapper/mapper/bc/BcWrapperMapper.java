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
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyWrap;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Aria;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.Kalyna;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.SEED;
import com.ibm.mapper.model.algorithms.gost.CryptoPro;
import com.ibm.mapper.model.algorithms.gost.GOST28147;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcWrapperMapper implements IMapper {

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
            case "AESWrapEngine", "AESWrapPadEngine", "RFC3394WrapEngine", "RFC5649WrapEngine" ->
                    Optional.of(new AES(KeyWrap.class, detectionLocation));
            case "ARIAWrapEngine", "ARIAWrapPadEngine" ->
                    Optional.of(new Aria(KeyWrap.class, new Aria(detectionLocation)));
            case "CamelliaWrapEngine" ->
                    Optional.of(new Camellia(KeyWrap.class, new Camellia(detectionLocation)));
            case "CryptoProWrapEngine" -> Optional.of(new CryptoPro(detectionLocation));
            case "DESedeWrapEngine" ->
                    Optional.of(new DESede(KeyWrap.class, new DESede(detectionLocation)));
            case "GOST28147WrapEngine" ->
                    Optional.of(new GOST28147(KeyWrap.class, new GOST28147(detectionLocation)));
            case "RC2WrapEngine" -> Optional.of(new RC2(KeyWrap.class, new RC2(detectionLocation)));
            case "SEEDWrapEngine" ->
                    Optional.of(new SEED(KeyWrap.class, new SEED(detectionLocation)));
            case "DSTU7624WrapEngine" ->
                    Optional.of(new Kalyna(KeyWrap.class, new Kalyna(detectionLocation)));
            case "RFC3211WrapEngine" ->
                    Optional.of(new RC2(KeyWrap.class, new RC2(detectionLocation)));
            default -> {
                final Algorithm algorithm =
                        new Algorithm(streamCipherString, BlockCipher.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
