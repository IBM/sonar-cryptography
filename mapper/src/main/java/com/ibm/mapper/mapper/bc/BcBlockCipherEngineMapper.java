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
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Aria;
import com.ibm.mapper.model.algorithms.Blowfish;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.IDEA;
import com.ibm.mapper.model.algorithms.Kalyna;
import com.ibm.mapper.model.algorithms.LEA;
import com.ibm.mapper.model.algorithms.NOEKEON;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC5;
import com.ibm.mapper.model.algorithms.RC6;
import com.ibm.mapper.model.algorithms.SEED;
import com.ibm.mapper.model.algorithms.SM4;
import com.ibm.mapper.model.algorithms.Serpent;
import com.ibm.mapper.model.algorithms.Skipjack;
import com.ibm.mapper.model.algorithms.Threefish;
import com.ibm.mapper.model.algorithms.Twofish;
import com.ibm.mapper.model.algorithms.cast.CAST128;
import com.ibm.mapper.model.algorithms.cast.CAST256;
import com.ibm.mapper.model.algorithms.gost.GOST28147;
import com.ibm.mapper.model.algorithms.gost.GOSTR34122015;
import com.ibm.mapper.model.algorithms.shacal.SHACAL2;
import com.ibm.mapper.model.algorithms.tea.TEA;
import com.ibm.mapper.model.algorithms.tea.XTEA;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcBlockCipherEngineMapper implements IMapper {

    private final Class<? extends IPrimitive> asKind;

    public BcBlockCipherEngineMapper(Class<? extends IPrimitive> asKind) {
        this.asKind = asKind;
    }

    @Override
    @Nonnull
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        Optional<? extends INode> node = map(str, detectionLocation);
        if (node.isPresent()) {
            return Optional.of(new Algorithm((IAlgorithm) node.get(), asKind));
        }
        return Optional.empty();
    }

    @Nonnull
    private Optional<? extends INode> map(
            @Nonnull String blockCipherString, @Nonnull DetectionLocation detectionLocation) {
        return switch (blockCipherString) {
            case "AESEngine" -> Optional.of(new AES(detectionLocation));
            case "AESFastEngine" -> Optional.of(new AES(detectionLocation));
            case "AESLightEngine" -> Optional.of(new AES(detectionLocation));
            case "ARIAEngine" -> Optional.of(new Aria(detectionLocation));
            case "BlowfishEngine" -> Optional.of(new Blowfish(detectionLocation));
            case "CamelliaEngine" -> Optional.of(new Camellia(detectionLocation));
            case "CamelliaLightEngine" -> Optional.of(new Camellia(detectionLocation));
            case "CAST5Engine" -> Optional.of(new CAST128(detectionLocation));
            case "CAST6Engine" -> Optional.of(new CAST256(detectionLocation));
            case "DESedeEngine" -> Optional.of(new DESede(detectionLocation));
            case "DESEngine" -> Optional.of(new DES(detectionLocation));
            case "DSTU7624Engine" -> Optional.of(new Kalyna(detectionLocation));
            case "GOST28147Engine" -> Optional.of(new GOST28147(detectionLocation));
            case "GOST3412_2015Engine" -> Optional.of(new GOSTR34122015(detectionLocation));
            case "IDEAEngine" -> Optional.of(new IDEA(detectionLocation));
            case "LEAEngine" -> Optional.of(new LEA(detectionLocation));
            case "NoekeonEngine" -> Optional.of(new NOEKEON(detectionLocation));
            case "NullEngine" ->
                    Optional.of(new Algorithm("Null", BlockCipher.class, detectionLocation));
            case "RC2Engine" -> Optional.of(new RC2(detectionLocation));
            case "RC532Engine" -> Optional.of(new RC5(64, detectionLocation));
            case "RC564Engine" -> Optional.of(new RC5(128, detectionLocation));
            case "RC6Engine" -> Optional.of(new RC6(detectionLocation));
            case "RijndaelEngine" -> Optional.of(new AES(detectionLocation));
            case "SEEDEngine" -> Optional.of(new SEED(detectionLocation));
            case "SerpentEngine" -> Optional.of(new Serpent(detectionLocation));
            case "Shacal2Engine" -> Optional.of(new SHACAL2(detectionLocation));
            case "SkipjackEngine" -> Optional.of(new Skipjack(detectionLocation));
            case "SM4Engine" -> Optional.of(new SM4(detectionLocation));
            case "TEAEngine" -> Optional.of(new TEA(detectionLocation));
            case "ThreefishEngine" -> Optional.of(new Threefish(detectionLocation));
            case "TnepresEngine" -> Optional.of(new Serpent(detectionLocation));
            case "TwofishEngine" -> Optional.of(new Twofish(detectionLocation));
            case "XTEAEngine" -> Optional.of(new XTEA(detectionLocation));

            default -> {
                final Algorithm algorithm =
                        new Algorithm(blockCipherString, BlockCipher.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
