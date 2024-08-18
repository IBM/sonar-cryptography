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

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.rules.detection.hash.CryptographyHash;
import com.ibm.plugin.rules.detection.symmetric.CryptographyCipher;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PythonKeyContextTranslator {

    private PythonKeyContextTranslator() {
        // private
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(PythonKeyContextTranslator.class);

    @Nonnull
    public static Optional<INode> translateForKeyContext(
            @Nonnull final IValue<Tree> value,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm) {
            return translateKeyContextAlgorithm(detectedAlgorithm, kind, detectionLocation);
        } else if (value instanceof KeySize<Tree> keySize) {
            return translateKeyContextKeySize(keySize, kind, detectionLocation);
        } else if (value instanceof KeyAction<Tree> keyAction) {
            return translateKeyContextKeyAction(keyAction, kind, detectionLocation);
        } else if (value instanceof AlgorithmParameter<Tree> algorithmParameter) {
            return translateKeyContextAlgorithmParameter(
                    algorithmParameter, kind, detectionLocation);
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateKeyContextAlgorithm(
            @Nonnull final com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        Algorithm algorithm;
        Cipher cipher;
        MessageDigest messageDigest;

        String detection = detectedAlgorithm.asString();
        switch (kind) {
            case PBKDF2HMAC, ConcatKDFHash, ConcatKDFHMAC, HKDF, HKDFExpand, KBKDFHMAC, X963KDF:
                // Hash algorithms [only the ones in `CryptographyHash.hashes` are supported]
                if (CryptographyHash.hashes.contains(detection)) {
                    String hashName = detection.replace('_', '-');
                    algorithm = new Algorithm(hashName, detectionLocation);
                    messageDigest = new MessageDigest(algorithm);
                    return Optional.of(messageDigest);
                }
                break;
            case KBKDFCMAC:
                if (CryptographyCipher.blockCiphers.contains(detection)) {
                    algorithm = new Algorithm(detection, detectionLocation);
                    cipher = new BlockCipher(algorithm, null, null);
                    return Optional.of(cipher);
                }
                break;
            default:
                break;
        }

        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateKeyContextKeySize(
            @Nonnull final KeySize<Tree> keySize,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        switch (kind) {
            case PBKDF2HMAC,
                    SCRYPT,
                    ConcatKDFHash,
                    ConcatKDFHMAC,
                    HKDF,
                    HKDFExpand,
                    KBKDFHMAC,
                    KBKDFCMAC,
                    X963KDF:
                return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
            default:
                break;
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateKeyContextKeyAction(
            @Nonnull final KeyAction<Tree> keyAction,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        switch (kind) {
            case PBKDF2HMAC, SCRYPT:
                return Optional.of(
                        new PasswordBasedKeyDerivationFunction(
                                new Algorithm(kind.name(), detectionLocation)));
            case ConcatKDFHash, ConcatKDFHMAC, HKDF, HKDFExpand, KBKDFHMAC, KBKDFCMAC, X963KDF:
                return Optional.of(
                        new KeyDerivationFunction(new Algorithm(kind.name(), detectionLocation)));
            default:
                break;
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateKeyContextAlgorithmParameter(
            @Nonnull final AlgorithmParameter<Tree> algorithmParameter,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        switch (kind) {
            case PBKDF2HMAC:
                try {
                    Integer numberOfIterations = Integer.valueOf(algorithmParameter.asString());
                    return Optional.of(
                            new NumberOfIterations(numberOfIterations, detectionLocation));
                } catch (NumberFormatException e) {
                    // Handle the case where the string cannot be converted to an integer
                    LOGGER.debug("Error: Unable to convert the string to an integer.");
                    break;
                }
            default:
                break;
        }
        return Optional.empty();
    }
}
