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
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.Kalyna;
import com.ibm.mapper.model.mode.CTS;
import com.ibm.mapper.model.mode.XTS;
import com.ibm.mapper.model.padding.PKCS7;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcBufferedBlockCipherMapper implements IMapper {

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
            @Nonnull String blockCipherString, @Nonnull DetectionLocation detectionLocation) {
        return switch (blockCipherString) {
            case "CTSBlockCipher", "OldCTSBlockCipher", "NISTCTSBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(new CTS(detectionLocation), BlockCipher.class));
            case "KXTSBlockCipher" ->
                    Optional.of(
                            Utils.cipherWithMode(
                                    new Kalyna(detectionLocation), new XTS(detectionLocation)));
            case "PaddedBufferedBlockCipher[PKCS7]" ->
                    Optional.of(
                            Utils.unknownWithPadding(
                                    new PKCS7(detectionLocation), BlockCipher.class));
            case "BufferedBlockCipher",
                    "DefaultBufferedBlockCipher",
                    "PaddedBlockCipher",
                    "PaddedBufferedBlockCipher" ->
                    Optional.of(Utils.unknown(BlockCipher.class, detectionLocation));
            default -> {
                Mode mode = new Mode(blockCipherString, detectionLocation);
                mode.put(new Unknown(detectionLocation));
                yield Optional.of(Utils.unknownWithMode(mode, BlockCipher.class));
            }
        };
    }
}
