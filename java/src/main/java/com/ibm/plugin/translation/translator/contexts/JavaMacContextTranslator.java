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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.AbstractContextTranslator;
import com.ibm.mapper.IContextTranslationWithKind;
import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.jca.JcaMacMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.translator.JavaTranslator;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaMacContextTranslator extends AbstractContextTranslator
        implements IContextTranslationWithKind<Tree, MacContext.Kind> {

    private static final Logger LOGGER = Loggers.get(JavaMacContextTranslator.class);

    public JavaMacContextTranslator(@NotNull Configuration configuration) {
        super(configuration);
    }

    @NotNull @Override
    public Optional<INode> translate(
            @NotNull IValue<Tree> value,
            @NotNull MacContext.Kind kind,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree>) {
            JcaMacMapper jcaMacMapper = new JcaMacMapper();
            return jcaMacMapper
                    .parse(value.asString(), detectionLocation, configuration)
                    .map(
                            algo -> {
                                algo.append(new Digest(detectionLocation));
                                algo.append(new Tag(detectionLocation));
                                return algo;
                            });
        } else if (value instanceof ValueAction<Tree> valueAction) {
            // TODO: Write a mapper
            Algorithm baseAlgorithm;
            Algorithm macAlgorithm;
            BlockCipher blockCipher;
            StreamCipher streamCipher;
            MessageDigest messageDigest;
            Mac mac;
            Mode mode;
            switch (valueAction.asString()) {
                case "Blake3Mac":
                    /* TODO: is this the correct MAC name? */
                    macAlgorithm = new Algorithm("BLAKE3-MAC", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("BLAKE", detectionLocation);
                    messageDigest = new MessageDigest(baseAlgorithm, detectionLocation);
                    mac.append(messageDigest);
                    break;
                case "BlockCipherMac", "CBCBlockCipherMac":
                    macAlgorithm =
                            new Algorithm("CBC-MAC-" + JavaTranslator.UNKNOWN, detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    mode = new Mode("CBC", detectionLocation);
                    mac.append(mode);
                    break;
                case "CFBBlockCipherMac":
                    macAlgorithm =
                            new Algorithm("CFB-MAC-" + JavaTranslator.UNKNOWN, detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    mode = new Mode("CFB", detectionLocation);
                    mac.append(mode);
                    break;
                case "CMac", "CMacWithIV":
                    macAlgorithm =
                            new Algorithm("CMAC-" + JavaTranslator.UNKNOWN, detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);
                    break;
                case "DSTU7564Mac":
                    /* TODO: is this the correct MAC name? */
                    macAlgorithm = new Algorithm("DSTU 7564-MAC", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("DSTU 7564", detectionLocation);
                    messageDigest = new MessageDigest(baseAlgorithm, detectionLocation);
                    mac.append(messageDigest);
                    break;
                case "DSTU7624Mac":
                    /* TODO: is this the correct MAC name? */
                    macAlgorithm = new Algorithm("DSTU 7624:2014-MAC", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("DSTU 7624:2014", detectionLocation);
                    blockCipher = new BlockCipher(baseAlgorithm, null, null, detectionLocation);
                    mac.append(blockCipher);
                    break;
                case "GMac", "KGMac":
                    macAlgorithm =
                            new Algorithm("GMAC-" + JavaTranslator.UNKNOWN, detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    mode = new Mode("GCM", detectionLocation);
                    mac.append(mode);
                    break;
                case "GOST28147Mac":
                    /* TODO: is this the correct MAC name? */
                    macAlgorithm = new Algorithm("GOST 28147-89-MAC", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("GOST 28147-89", detectionLocation);
                    blockCipher = new BlockCipher(baseAlgorithm, null, null, detectionLocation);
                    mac.append(blockCipher);
                    break;
                case "HMac", "OldHMac":
                    macAlgorithm =
                            new Algorithm("HMAC-" + JavaTranslator.UNKNOWN, detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);
                    break;
                case "ISO9797Alg3Mac":
                    macAlgorithm =
                            new Algorithm("CBC-MAC-" + JavaTranslator.UNKNOWN, detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    mode = new Mode("CBC", detectionLocation);
                    mac.append(mode);

                    /* TODO: add this default BlockCipher value in the enrichment */
                    /* baseAlgorithm = new Algorithm("DES", detectionLocation);
                    blockCipher = new BlockCipher(baseAlgorithm, null, null, detectionLocation);
                    mac.append(blockCipher); */
                    break;
                case "KMAC":
                    macAlgorithm = new Algorithm("KMAC", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("Keccak", detectionLocation);
                    messageDigest = new MessageDigest(baseAlgorithm, detectionLocation);
                    mac.append(messageDigest);
                    break;
                case "Poly1305":
                    macAlgorithm = new Algorithm("Poly1305", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);
                    break;
                case "SipHash":
                    /* TODO: is this the correct MAC name? */
                    macAlgorithm = new Algorithm("SipHash", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("SipHash", detectionLocation);
                    messageDigest = new MessageDigest(baseAlgorithm, detectionLocation);
                    mac.append(messageDigest);
                    break;
                case "SipHash128":
                    /* TODO: is this the correct MAC name? */
                    macAlgorithm = new Algorithm("SipHash", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("SipHash", detectionLocation);
                    messageDigest = new MessageDigest(baseAlgorithm, detectionLocation);

                    DigestSize digestSize = new DigestSize(128, detectionLocation);
                    messageDigest.append(digestSize);

                    mac.append(messageDigest);
                    break;
                case "SkeinMac":
                    macAlgorithm = new Algorithm("Skein", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("Threefish", detectionLocation);
                    blockCipher = new BlockCipher(baseAlgorithm, null, null, detectionLocation);
                    mac.append(blockCipher);
                    break;
                case "VMPCMac":
                    /* TODO: is this the correct MAC name? */
                    macAlgorithm = new Algorithm("VMPC", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("VMPC", detectionLocation);
                    streamCipher = new StreamCipher(baseAlgorithm, null, null, detectionLocation);
                    mac.append(streamCipher);
                    break;
                case "Zuc128Mac":
                    /* TODO: is this the correct MAC name? */
                    macAlgorithm = new Algorithm("ZUC-128", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("ZUC-128", detectionLocation);
                    streamCipher = new StreamCipher(baseAlgorithm, null, null, detectionLocation);
                    mac.append(streamCipher);
                    break;
                case "Zuc256Mac":
                    /* TODO: is this the correct MAC name? */
                    macAlgorithm = new Algorithm("ZUC-256", detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);

                    baseAlgorithm = new Algorithm("ZUC-256", detectionLocation);
                    streamCipher = new StreamCipher(baseAlgorithm, null, null, detectionLocation);
                    mac.append(streamCipher);
                    break;
                default:
                    LOGGER.warn("An unknown Mac algorithm was used: its translation may be wrong");
                    // Default translation: simply return a Mac node
                    macAlgorithm = new Algorithm(valueAction.asString(), detectionLocation);
                    mac = new Mac(macAlgorithm, detectionLocation);
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
        }
        return Optional.empty();
    }
}
