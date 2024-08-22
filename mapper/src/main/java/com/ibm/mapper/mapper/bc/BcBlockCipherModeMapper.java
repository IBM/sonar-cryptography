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
import com.ibm.mapper.model.algorithms.gost.GOST28147;
import com.ibm.mapper.model.algorithms.gost.GOSTR34122015;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.OFB;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcBlockCipherModeMapper implements IMapper {

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
            case "CBCBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(new CBC(detectionLocation), BlockCipher.class));
            case "CFBBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(new CFB(detectionLocation), BlockCipher.class));
            case "G3413CBCBlockCipher" ->
                    Optional.of(
                            Utils.cipherWithMode(
                                    new GOSTR34122015(detectionLocation),
                                    new CBC(detectionLocation)));
            case "G3413CFBBlockCipher" ->
                    Optional.of(
                            Utils.cipherWithMode(
                                    new GOSTR34122015(detectionLocation),
                                    new CFB(detectionLocation)));
            case "G3413CTRBlockCipher" ->
                    Optional.of(
                            Utils.cipherWithMode(
                                    new GOSTR34122015(detectionLocation),
                                    new CTR(detectionLocation)));
            case "G3413OFBBlockCipher" ->
                    Optional.of(
                            Utils.cipherWithMode(
                                    new GOSTR34122015(detectionLocation),
                                    new OFB(detectionLocation)));
            case "GCFBBlockCipher" ->
                    Optional.of(
                            Utils.cipherWithMode(
                                    new GOST28147(detectionLocation), new CFB(detectionLocation)));
            case "GOFBBlockCipher" ->
                    Optional.of(
                            Utils.cipherWithMode(
                                    new GOST28147(detectionLocation), new OFB(detectionLocation)));
            case "OFBBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(new OFB(detectionLocation), BlockCipher.class));
            case "KCTRBlockCipher" ->
                    Optional.of(
                            Utils.cipherWithMode(
                                    new Kalyna(detectionLocation), new CTR(detectionLocation)));
            case "OpenPGPCFBBlockCipher", "PGPCFBBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(new CFB(detectionLocation), BlockCipher.class));
            case "SICBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(new CTR(detectionLocation), BlockCipher.class));
            default -> {
                Mode mode = new Mode(blockCipherString, detectionLocation);
                mode.put(new Unknown(detectionLocation));
                yield Optional.of(Utils.unknownWithMode(mode, BlockCipher.class));
            }
        };
    }
}
