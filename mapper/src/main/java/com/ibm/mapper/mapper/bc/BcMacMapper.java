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
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.KMAC;
import com.ibm.mapper.model.algorithms.Kalyna;
import com.ibm.mapper.model.algorithms.Kupyna;
import com.ibm.mapper.model.algorithms.Poly1305;
import com.ibm.mapper.model.algorithms.SipHash;
import com.ibm.mapper.model.algorithms.Skein;
import com.ibm.mapper.model.algorithms.ZUC;
import com.ibm.mapper.model.algorithms.blake.BLAKE3;
import com.ibm.mapper.model.algorithms.gost.GOST28147;
import com.ibm.mapper.model.algorithms.vmpc.VMPCMAC;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.GMAC;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcMacMapper implements IMapper {

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
            @Nonnull String macString, @Nonnull DetectionLocation detectionLocation) {
        return switch (macString) {
            case "HMac" -> Optional.of(new HMAC(detectionLocation));
            case "OldHMac" -> Optional.of(new HMAC(detectionLocation));
            case "Blake3Mac" -> Optional.of(new BLAKE3(Mac.class, new BLAKE3(detectionLocation)));
            case "BlockCipherMac", "CBCBlockCipherMac", "ISO9797Alg3Mac" ->
                    Optional.of(Utils.unknownWithMode(new CBC(detectionLocation), Mac.class));
            case "CFBBlockCipherMac" ->
                    Optional.of(Utils.unknownWithMode(new CFB(detectionLocation), Mac.class));
            case "CMac", "CMacWithIV" -> Optional.of(new CMAC(detectionLocation));
            case "DSTU7564Mac" -> Optional.of(new Kupyna(Mac.class, new Kupyna(detectionLocation)));
            case "DSTU7624Mac" -> {
                yield Optional.of(new Kalyna(Mac.class, new Kalyna(detectionLocation)));
            }
            case "GMac" ->
                    Optional.of(Utils.unknownWithMode(new GMAC(detectionLocation), Mac.class));
            case "KGMac" ->
                    Optional.of(
                            Utils.cipherWithMode(
                                    new Kalyna(Mac.class, new Kalyna(detectionLocation)),
                                    new GMAC(detectionLocation)));
            case "GOST28147Mac" ->
                    Optional.of(new GOST28147(Mac.class, new GOST28147(detectionLocation)));
            case "KMAC" -> Optional.of(new KMAC(detectionLocation));
            case "Poly1305" ->
                    Optional.of(new Poly1305(Mac.class, new Poly1305(detectionLocation)));
            case "SipHash" -> Optional.of(new SipHash(detectionLocation));
            case "SipHash128" -> Optional.of(new SipHash(128, detectionLocation));
            case "SkeinMac" -> Optional.of(new Skein(Mac.class, new Skein(detectionLocation)));
            case "VMPCMac" -> Optional.of(new VMPCMAC(detectionLocation));
            case "Zuc128Mac" -> Optional.of(new ZUC(Mac.class, new ZUC(128, detectionLocation)));
            case "Zuc256Mac" -> Optional.of(new ZUC(Mac.class, new ZUC(256, detectionLocation)));
            default -> {
                final Algorithm algorithm = new Algorithm(macString, Mac.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
