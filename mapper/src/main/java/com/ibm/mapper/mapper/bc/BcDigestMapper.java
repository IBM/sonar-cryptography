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
import com.ibm.mapper.model.algorithms.HarakaV2;
import com.ibm.mapper.model.algorithms.KMAC;
import com.ibm.mapper.model.algorithms.KangarooTwelve;
import com.ibm.mapper.model.algorithms.Keccak;
import com.ibm.mapper.model.algorithms.Kupyna;
import com.ibm.mapper.model.algorithms.LMS;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD4;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.MarsupilamiFourteen;
import com.ibm.mapper.model.algorithms.ParallelHash;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.model.algorithms.Skein;
import com.ibm.mapper.model.algorithms.Tiger;
import com.ibm.mapper.model.algorithms.TupleHash;
import com.ibm.mapper.model.algorithms.Whirlpool;
import com.ibm.mapper.model.algorithms.Xoodyak;
import com.ibm.mapper.model.algorithms.ascon.AsconHash;
import com.ibm.mapper.model.algorithms.ascon.AsconXof;
import com.ibm.mapper.model.algorithms.blake.BLAKE2X;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.model.algorithms.blake.BLAKE3;
import com.ibm.mapper.model.algorithms.gost.GOST341194;
import com.ibm.mapper.model.algorithms.gost.GOSTR341112;
import com.ibm.mapper.model.algorithms.isap.Isap;
import com.ibm.mapper.model.algorithms.photonbeetle.PhotonBeetleHash;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
import com.ibm.mapper.model.algorithms.sparkle.Esch;
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
            case "DSTU7564Digest" -> Optional.of(new Kupyna(detectionLocation));
            case "GOST3411_2012_256Digest" -> Optional.of(new GOSTR341112(256, detectionLocation));
            case "GOST3411_2012_512Digest" -> Optional.of(new GOSTR341112(512, detectionLocation));
            case "GOST3411Digest" -> Optional.of(new GOST341194(detectionLocation));
            case "Haraka256Digest" -> Optional.of(new HarakaV2(256, detectionLocation));
            case "Haraka512Digest" -> Optional.of(new HarakaV2(512, detectionLocation));
            case "HarakaBase" -> Optional.of(new HarakaV2(detectionLocation));
            case "ISAPDigest" ->
                    Optional.of(new Isap(MessageDigest.class, new Isap(detectionLocation)));
            case "KangarooTwelve" -> Optional.of(new KangarooTwelve(detectionLocation));
            case "KeccakDigest" -> Optional.of(new Keccak(detectionLocation));
            case "KMAC" -> Optional.of(new KMAC(MessageDigest.class, new KMAC(detectionLocation)));
            case "LMSContext" -> Optional.of(new LMS(MessageDigest.class, detectionLocation));
            case "MarsupilamiFourteen" -> Optional.of(new MarsupilamiFourteen(detectionLocation));
            case "MD2Digest" -> Optional.of(new MD2(detectionLocation));
            case "MD4Digest" -> Optional.of(new MD4(detectionLocation));
            case "MD5Digest" -> Optional.of(new MD5(detectionLocation));
            case "NullDigest" -> Optional.empty();
            case "ParallelHash" -> Optional.of(new ParallelHash(detectionLocation));
            case "PhotonBeetleDigest" -> Optional.of(new PhotonBeetleHash(detectionLocation));
            case "RIPEMD128Digest" -> Optional.of(new RIPEMD(128, detectionLocation));
            case "RIPEMD160Digest" -> Optional.of(new RIPEMD(160, detectionLocation));
            case "RIPEMD256Digest" -> Optional.of(new RIPEMD(256, detectionLocation));
            case "RIPEMD320Digest" -> Optional.of(new RIPEMD(320, detectionLocation));
            case "SHA1Digest" -> Optional.of(new SHA(detectionLocation));
            case "SHA224Digest" -> Optional.of(new SHA2(224, detectionLocation));
            case "SHA256Digest" -> Optional.of(new SHA2(256, detectionLocation));
            case "SHA384Digest" -> Optional.of(new SHA3(384, detectionLocation));
            case "SHA3Digest" -> Optional.of(new SHA3(detectionLocation));
            case "SHA512Digest" -> Optional.of(new SHA2(512, detectionLocation));
            case "SHA512tDigest" -> Optional.of(new SHA2(512, detectionLocation));
            case "SHAKEDigest" -> Optional.of(new SHAKE(detectionLocation));
            case "SkeinDigest" -> Optional.of(new Skein(detectionLocation));
            case "SM3Digest" -> Optional.of(new SM3(detectionLocation));
            case "SparkleDigest" -> Optional.of(new Esch(detectionLocation));
            case "TigerDigest" -> Optional.of(new Tiger(192, detectionLocation));
            case "TupleHash" -> Optional.of(new TupleHash(detectionLocation));
            case "WhirlpoolDigest" -> Optional.of(new Whirlpool(detectionLocation));
            case "XoodyakDigest" -> Optional.of(new Xoodyak(detectionLocation));
            default -> {
                final Algorithm algorithm =
                        new Algorithm(digestString, MessageDigest.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
