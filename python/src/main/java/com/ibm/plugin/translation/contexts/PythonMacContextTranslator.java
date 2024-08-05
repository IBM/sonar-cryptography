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
package com.ibm.plugin.translation.contexts;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.rules.detection.hash.CryptographyHash;
import com.ibm.plugin.rules.detection.symmetric.CryptographyCipher;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PythonMacContextTranslator {

    private PythonMacContextTranslator() {
        // private
    }

    @Nonnull
    public static Optional<INode> translateForMacContext(
            @Nonnull final IValue<Tree> value,
            @Nonnull MacContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm) {
            return translateMacContextAlgorithm(detectedAlgorithm, kind, detectionLocation);
        } else if (value instanceof CipherAction<Tree> cipherAction) {
            return translateMacContextCipherAction(cipherAction, kind, detectionLocation);
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateMacContextAlgorithm(
            @Nonnull final com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm,
            @Nonnull MacContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        Algorithm algorithm;
        Cipher cipher;
        MessageDigest messageDigest;
        Mac mac;
        String detection = detectedAlgorithm.asString();
        switch (kind) {
            case CMAC:
                // When calling the `CMAC` constructor
                // Algorithms [only the ones in `CryptographyCipher.blockCiphers` are supported]
                algorithm = new Algorithm(detection + "-CMAC", detectionLocation);
                if (CryptographyCipher.blockCiphers.contains(detection)) {
                    cipher = new BlockCipher(algorithm, null, null);
                    mac = new Mac(cipher);
                    return Optional.of(mac);
                }
                break;
            case HMAC:
                // When calling the `HMAC` constructor
                // Hash algorithms [only the ones in `CryptographyHash.hashes` are supported]
                if (CryptographyHash.hashes.contains(detection)) {
                    String hashName = detection.replace('_', '-');
                    algorithm = new Algorithm("HMAC-" + hashName, detectionLocation);
                    messageDigest = new MessageDigest(algorithm);
                    mac = new Mac(messageDigest);
                    return Optional.of(mac);
                }
                break;
            default:
                break;
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateMacContextCipherAction(
            @Nonnull final CipherAction<Tree> cipherAction,
            @Nonnull MacContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        Algorithm algorithm;
        Mac mac;
        switch (cipherAction.getAction()) {
            case MAC:
                algorithm = new Algorithm(kind.name(), detectionLocation);
                mac = new Mac(algorithm);
                return Optional.of(mac);
            default:
                break;
        }
        return Optional.empty();
    }
}
