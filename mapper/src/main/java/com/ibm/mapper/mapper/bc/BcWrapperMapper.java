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
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.AESWrap;
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
            /* TODO: how should Wrap be handled? Should all BlockCiphers be duplicated with a Wrap version like for AES? */
            case "AESWrapEngine" -> Optional.of(new AESWrap(detectionLocation));
            case "AESWrapPadEngine" -> Optional.of(new AESWrap(detectionLocation));
            // case "ARIAWrapEngine" -> Optional.of();
            // case "ARIAWrapPadEngine" -> Optional.of();
            // case "CamelliaWrapEngine" -> Optional.of();
            // case "CryptoProWrapEngine" -> Optional.of();
            // case "DESedeWrapEngine" -> Optional.of();
            // case "GOST28147WrapEngine" -> Optional.of();
            // case "RC2WrapEngine" -> Optional.of();
            // case "SEEDWrapEngine" -> Optional.of();
            // case "DSTU7624WrapEngine" -> Optional.of();
            // case "RFC3211WrapEngine" -> Optional.of();
            // case "RFC3394WrapEngine" -> Optional.of();
            // case "RFC5649WrapEngine" -> Optional.of();
            default -> {
                final Algorithm algorithm =
                        new Algorithm(streamCipherString, BlockCipher.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
