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
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.SHAKE;
import com.ibm.mapper.model.algorithms.ascon.AsconHash;
import com.ibm.mapper.model.algorithms.ascon.AsconXof;
import com.ibm.mapper.model.algorithms.blake.BLAKE2X;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.model.algorithms.blake.BLAKE3;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcDigestMapper implements IMapper {

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
            @Nonnull String digestString, @Nonnull DetectionLocation detectionLocation) {
        return switch (digestString) {
            case "AsconDigest" -> Optional.of(new AsconHash(detectionLocation));
            case "AsconXof" -> Optional.of(new AsconXof(detectionLocation));
            case "Blake2bDigest" -> Optional.of(new BLAKE2b(false, detectionLocation));
            case "Blake2bpDigest" -> Optional.of(new BLAKE2b(true, detectionLocation));
            case "Blake2sDigest" -> Optional.of(new BLAKE2s(false, detectionLocation));
            case "Blake2spDigest" -> Optional.of(new BLAKE2s(true, detectionLocation));
            case "Blake2xsDigest" ->
                    Optional.of(
                            new BLAKE2X(new BLAKE2s(false, detectionLocation), detectionLocation));
            case "Blake3Digest" -> Optional.of(new BLAKE3(detectionLocation));
            case "CSHAKEDigest" -> Optional.of(new SHAKE(detectionLocation));
            case "DSTU7564Digest" -> Optional.of();
            case "GOST3411_2012_256Digest" -> Optional.of();
            case "GOST3411_2012_512Digest" -> Optional.of();
            case "GOST3411_2012Digest" -> Optional.of();
            case "GOST3411Digest" -> Optional.of();
            case "Haraka256Digest" -> Optional.of();
            case "Haraka512Digest" -> Optional.of();
            case "HarakaBase" -> Optional.of();
            case "ISAPDigest" -> Optional.of();
            case "KangarooTwelve" -> Optional.of();
            case "KeccakDigest" -> Optional.of();
            case "KMAC" -> Optional.of();
            case "LMSContext" -> Optional.of();
            case "MarsupilamiFourteen" -> Optional.of();
            case "MD2Digest" -> Optional.of();
            case "MD4Digest" -> Optional.of();
            case "MD5Digest" -> Optional.of();
            case "NullDigest" -> Optional.of();
            case "ParallelHash" -> Optional.of();
            case "PhotonBeetleDigest" -> Optional.of();
            case "RIPEMD128Digest" -> Optional.of();
            case "RIPEMD160Digest" -> Optional.of();
            case "RIPEMD256Digest" -> Optional.of();
            case "RIPEMD320Digest" -> Optional.of();
            case "SHA1Digest" -> Optional.of();
            case "SHA224Digest" -> Optional.of();
            case "SHA256Digest" -> Optional.of();
            case "SHA384Digest" -> Optional.of();
            case "SHA3Digest" -> Optional.of();
            case "SHA512Digest" -> Optional.of();
            case "SHA512tDigest" -> Optional.of();
            case "SHAKEDigest" -> Optional.of();
            case "SkeinDigest" -> Optional.of();
            case "SM3Digest" -> Optional.of();
            case "SparkleDigest" -> Optional.of();
            case "TigerDigest" -> Optional.of();
            case "TupleHash" -> Optional.of();
            case "WhirlpoolDigest" -> Optional.of();
            case "XoodyakDigest" -> Optional.of();
            default -> {
                final Algorithm algorithm =
                        new Algorithm(digestString, MessageDigest.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
