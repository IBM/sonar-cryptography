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
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ChaCha20;
import com.ibm.mapper.model.algorithms.ChaCha20Poly1305;
import com.ibm.mapper.model.algorithms.Xoodyak;
import com.ibm.mapper.model.algorithms.ascon.Ascon;
import com.ibm.mapper.model.algorithms.elephant.Elephant;
import com.ibm.mapper.model.algorithms.grain.Grain128AEAD;
import com.ibm.mapper.model.algorithms.isap.Isap;
import com.ibm.mapper.model.algorithms.photonbeetle.PhotonBeetleAEAD;
import com.ibm.mapper.model.algorithms.sparkle.Schwaemm;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.EAX;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.GCMSIV;
import com.ibm.mapper.model.mode.OCB;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcAeadMapper implements IMapper {

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
            @Nonnull String aeadString, @Nonnull DetectionLocation detectionLocation) {
        return switch (aeadString) {
            case "AsconEngine" -> Optional.of(new Ascon(detectionLocation));
            case "ElephantEngine" -> Optional.of(new Elephant(detectionLocation));
            case "Grain128AEADEngine" -> Optional.of(new Grain128AEAD(detectionLocation));
            case "IsapEngine" -> Optional.of(new Isap(detectionLocation));
            case "PhotonBeetleEngine" -> Optional.of(new PhotonBeetleAEAD(detectionLocation));
            case "SparkleEngine" -> Optional.of(new Schwaemm(detectionLocation));
            case "XoodyakEngine" ->
                    Optional.of(new Xoodyak(AuthenticatedEncryption.class, detectionLocation));

            case "CCMBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(
                                    new CCM(detectionLocation), AuthenticatedEncryption.class));
            case "EAXBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(
                                    new EAX(detectionLocation), AuthenticatedEncryption.class));
            case "GCMBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(
                                    new GCM(detectionLocation), AuthenticatedEncryption.class));
            case "GCMSIVBlockCipher" ->
                    /* The default `new GCMSIVBlockCipher()` is instantiated with an `AESEngine` */
                    Optional.of(
                            Utils.cipherWithMode(
                                    new AES(
                                            AuthenticatedEncryption.class,
                                            new AES(detectionLocation)),
                                    new GCMSIV(detectionLocation)));
            case "KCCMBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(
                                    new CCM(detectionLocation), AuthenticatedEncryption.class));
            case "KGCMBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(
                                    new GCM(detectionLocation), AuthenticatedEncryption.class));
            case "OCBBlockCipher" ->
                    Optional.of(
                            Utils.unknownWithMode(
                                    new OCB(detectionLocation), AuthenticatedEncryption.class));

            case "ChaCha20Poly1305" -> Optional.of(new ChaCha20Poly1305(detectionLocation));
            case "ChaCha20Poly1305[WITH_MAC]" ->
                    Optional.of(
                            new ChaCha20(
                                    AuthenticatedEncryption.class,
                                    new ChaCha20(detectionLocation)));

            default -> {
                final Algorithm algorithm =
                        new Algorithm(aeadString, AuthenticatedEncryption.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
