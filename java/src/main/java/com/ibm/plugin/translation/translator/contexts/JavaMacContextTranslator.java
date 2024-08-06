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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.BlockSize;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.MacSize;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.mapper.mapper.jca.JcaMacMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaMacContextTranslator extends JavaAbstractLibraryTranslator {
    private static final Logger LOGGER = LoggerFactory.getLogger(JavaMacContextTranslator.class);

    @Override
    protected @NotNull Optional<INode> translateJCA(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree>) {
            JcaMacMapper jcaMacMapper = new JcaMacMapper();
            return jcaMacMapper
                    .parse(value.asString(), detectionLocation)
                    .map(
                            algo -> {
                                algo.append(new Digest(detectionLocation));
                                algo.append(new Tag(detectionLocation));
                                return algo;
                            });
        } else if (value instanceof MacSize<Tree> macSize) {
            TagLength tagLength = new TagLength(macSize.getValue(), detectionLocation);
            return Optional.of(tagLength);
        } else if (value instanceof BlockSize<Tree> blockSizeDetection) {
            com.ibm.mapper.model.BlockSize blockSize =
                    new com.ibm.mapper.model.BlockSize(
                            blockSizeDetection.getValue(), detectionLocation);
            return Optional.of(blockSize);
        }
        return Optional.empty();
    }

    @Override
    protected @NotNull Optional<INode> translateBC(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        /*if (value instanceof ValueAction<Tree> valueAction) {
            Algorithm baseAlgorithm;
            Algorithm macAlgorithm;
            BlockCipher blockCipher;
            StreamCipher streamCipher;
            MessageDigest messageDigest;
            HMAC mac;
            Mode mode;
            switch (valueAction.asString()) {
                case "Blake3Mac":
                    macAlgorithm = new Algorithm("BLAKE3-MAC", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("BLAKE", detectionLocation);
                    messageDigest = new MessageDigest(baseAlgorithm);
                    mac.append(messageDigest);
                    break;
                case "BlockCipherMac", "CBCBlockCipherMac", "ISO9797Alg3Mac":
                    macAlgorithm =
                            new Algorithm("CBC-MAC-" + ITranslator.UNKNOWN, detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    mode = new Mode("CBC", detectionLocation);
                    mac.append(mode);
                    break;
                case "CFBBlockCipherMac":
                    macAlgorithm =
                            new Algorithm("CFB-MAC-" + ITranslator.UNKNOWN, detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    mode = new Mode("CFB", detectionLocation);
                    mac.append(mode);
                    break;
                case "CMac", "CMacWithIV":
                    macAlgorithm = new Algorithm("CMAC-" + ITranslator.UNKNOWN, detectionLocation);
                    mac = new HMAC(macAlgorithm);
                    break;
                case "DSTU7564Mac":
                    macAlgorithm = new Algorithm("DSTU 7564-MAC", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("DSTU 7564", detectionLocation);
                    messageDigest = new MessageDigest(baseAlgorithm);
                    mac.append(messageDigest);
                    break;
                case "DSTU7624Mac":
                    macAlgorithm = new Algorithm("DSTU 7624:2014-MAC", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("DSTU 7624:2014", detectionLocation);
                    blockCipher = new BlockCipher(baseAlgorithm, null, null);
                    mac.append(blockCipher);
                    break;
                case "GMac", "KGMac":
                    macAlgorithm = new Algorithm("GMAC-" + ITranslator.UNKNOWN, detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    mode = new Mode("GCM", detectionLocation);
                    mac.append(mode);
                    break;
                case "GOST28147Mac":
                    macAlgorithm = new Algorithm("GOST 28147-89-MAC", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("GOST 28147-89", detectionLocation);
                    blockCipher = new BlockCipher(baseAlgorithm, null, null);
                    mac.append(blockCipher);
                    break;
                case "HMac", "OldHMac":
                    macAlgorithm = new Algorithm("HMAC-" + ITranslator.UNKNOWN, detectionLocation);
                    mac = new HMAC(macAlgorithm);
                    break;
                case "KMAC":
                    macAlgorithm = new Algorithm("KMAC", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("Keccak", detectionLocation);
                    messageDigest = new MessageDigest(baseAlgorithm);
                    mac.append(messageDigest);
                    break;
                case "Poly1305":
                    macAlgorithm = new Algorithm("Poly1305", detectionLocation);
                    mac = new HMAC(macAlgorithm);
                    break;
                case "SipHash":
                    macAlgorithm = new Algorithm("SipHash", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("SipHash", detectionLocation);
                    messageDigest = new MessageDigest(baseAlgorithm);
                    mac.append(messageDigest);
                    break;
                case "SipHash128":
                    macAlgorithm = new Algorithm("SipHash", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("SipHash", detectionLocation);
                    messageDigest = new MessageDigest(baseAlgorithm);

                    DigestSize digestSize = new DigestSize(128, detectionLocation);
                    messageDigest.append(digestSize);

                    mac.append(messageDigest);
                    break;
                case "SkeinMac":
                    macAlgorithm = new Algorithm("Skein", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("Threefish", detectionLocation);
                    blockCipher = new BlockCipher(baseAlgorithm, null, null);
                    mac.append(blockCipher);
                    break;
                case "VMPCMac":
                    macAlgorithm = new Algorithm("VMPC", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("VMPC", detectionLocation);
                    streamCipher = new StreamCipher(baseAlgorithm, null, null);
                    mac.append(streamCipher);
                    break;
                case "Zuc128Mac":
                    macAlgorithm = new Algorithm("ZUC-128", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("ZUC-128", detectionLocation);
                    streamCipher = new StreamCipher(baseAlgorithm, null, null);
                    mac.append(streamCipher);
                    break;
                case "Zuc256Mac":
                    macAlgorithm = new Algorithm("ZUC-256", detectionLocation);
                    mac = new HMAC(macAlgorithm);

                    baseAlgorithm = new Algorithm("ZUC-256", detectionLocation);
                    streamCipher = new StreamCipher(baseAlgorithm, null, null);
                    mac.append(streamCipher);
                    break;
                default:
                    LOGGER.warn("An unknown Mac algorithm was used: its translation may be wrong");
                    // Default translation: simply return a Mac node
                    macAlgorithm = new Algorithm(valueAction.asString(), detectionLocation);
                    mac = new HMAC(macAlgorithm);
            }
            mac.append(new Tag(detectionLocation));
            mac.append(new Digest(detectionLocation));
            return Optional.of(mac);
        } else if (value instanceof MacSize<Tree> macSize) {
            TagLength tagLength = new TagLength(macSize.getValue(), detectionLocation);
            return Optional.of(tagLength);
        } else if (value instanceof BlockSize<Tree> blockSizeDetection) {
            com.ibm.mapper.model.BlockSize blockSize =
                    new com.ibm.mapper.model.BlockSize(
                            blockSizeDetection.getValue(), detectionLocation);
            return Optional.of(blockSize);
        }*/
        return Optional.empty();
    }
}
