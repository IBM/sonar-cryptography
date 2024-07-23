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
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.OptimalAsymmetricEncryptionPadding;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.rules.detection.symmetric.CryptographyCipher;
import com.ibm.plugin.translation.PythonTranslatorUtils;
import org.sonar.plugins.python.api.tree.Tree;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@SuppressWarnings("java:S1301")
public final class PythonCipherContextTranslator {

    private PythonCipherContextTranslator() {
        // private static
    }

    @Nonnull
    public static Optional<INode> translateForCipherContext(
            @Nonnull final IValue<Tree> value,
            @Nonnull CipherContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm) {
            return translateCipherContextAlgorithm(detectedAlgorithm, kind, detectionLocation);
        } else if (value instanceof CipherAction<Tree> cipherAction) {
            return translateCipherContextCipherAction(cipherAction, kind, detectionLocation);
        } else if (value instanceof KeySize<Tree> keySize) {
            return translateCipherContextKeySize(keySize, kind, detectionLocation);
        }

        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateCipherContextAlgorithm(
            @Nonnull final com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm,
            @Nonnull CipherContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        Algorithm algorithm;
        Cipher cipher;

        String detection = detectedAlgorithm.asString();
        switch (detection) {
            case "MGF1":
                return Optional.of(
                        new MaskGenerationFunction(
                                new Algorithm(detection, detectionLocation)));
            default:
                switch (kind) {
                    case NONE:
                        // When calling the `Cipher` constructor

                        // Algorithms [only the ones in `CryptographyCipher.blockCiphers` and
                        // `CryptographyCipher.streamCiphers` are supported]
                        algorithm = new Algorithm(detection, detectionLocation);
                        if (CryptographyCipher.blockCiphers.contains(detection)) {
                            cipher = new BlockCipher(algorithm, null, null);
                            return Optional.of(cipher);
                        } else if (CryptographyCipher.streamCiphers.contains(detection)) {
                            cipher = new StreamCipher(algorithm, null, null);
                            return Optional.of(cipher);
                        }

                        // Modes [only the ones in `CryptographyCipher.modes` are supported]
                        if (CryptographyCipher.modes.contains(detection)) {
                            Mode mode = new Mode(detection, detectionLocation);
                            return Optional.of(mode);
                        }
                        break;
                    case PKCS7, ANSIX923:
                        // Case of symmetric padding when the block size has been specified with
                        // a `block_size` attribute
                        List<String> algorithmsBlockSize128 =
                                List.of("AES", "AES128", "AES256", "Camellia", "SEED", "SM4");
                        if (algorithmsBlockSize128.contains(detection)) {
                            return Optional.of(
                                    paddingWithBlockSize(kind.name(), 128, detectionLocation));
                        }
                        List<String> algorithmsBlockSize64 =
                                List.of("TripleDES", "CAST5", "Blowfish", "IDEA");
                        if (algorithmsBlockSize64.contains(detection)) {
                            return Optional.of(
                                    paddingWithBlockSize(kind.name(), 64, detectionLocation));
                        }
                        break;
                    default:
                        break;
                }
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateCipherContextCipherAction(
            @Nonnull final CipherAction<Tree> cipherAction,
            @Nonnull CipherContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        Algorithm algorithm;
        Cipher cipher;
        Padding padding;

        switch (cipherAction.getAction()) {
            case DECRYPT:
                switch (kind) {
                    case Fernet:
                        algorithm = new Algorithm("Fernet", detectionLocation);
                        algorithm.append(new Decrypt(detectionLocation));
                        return Optional.of(algorithm);
                    case RSA:
                        algorithm = new Algorithm("RSA", detectionLocation);
                        algorithm.append(new Decrypt(detectionLocation));
                        return Optional.of(algorithm);
                    case CHACHA20POLY1305:
                        cipher =
                                PythonTranslatorUtils.generateNewStreamCipher(
                                        "ChaCha20", "Poly1305", detectionLocation);
                        cipher.append(new Decrypt(detectionLocation));
                        return Optional.of(cipher);
                    case NONE:
                        return Optional.of(new Decrypt(detectionLocation));
                    default:
                        if (kind.name().startsWith("AES")) {
                            // Cases "AESGCM", "AESGCMIV", "AESOCB3", "AESSIV", "AESCCM"
                            algorithm = new Algorithm("AES", detectionLocation);
                            cipher =
                                    new AuthenticatedEncryption(
                                            algorithm, null, null, null);
                            cipher.append(new Decrypt(detectionLocation));
                            return Optional.of(cipher);
                        }
                        break;
                }
                break;
            case ENCRYPT:
                switch (kind) {
                    case Fernet:
                        algorithm = new Algorithm("Fernet", detectionLocation);
                        algorithm.append(new Encrypt(detectionLocation));
                        return Optional.of(algorithm);
                    case RSA:
                        cipher =
                                new Cipher(
                                        new Algorithm("RSA", detectionLocation));
                        cipher.append(new Encrypt(detectionLocation));
                        return Optional.of(cipher);
                    case CHACHA20POLY1305:
                        cipher =
                                PythonTranslatorUtils.generateNewStreamCipher(
                                        "ChaCha20", "Poly1305", detectionLocation);
                        cipher.append(new Encrypt(detectionLocation));
                        return Optional.of(cipher);
                    case NONE:
                        return Optional.of(new Encrypt(detectionLocation));
                    default:
                        if (kind.name().startsWith("AES")) {
                            // Cases "AESGCM", "AESGCMIV", "AESOCB3", "AESSIV", "AESCCM"
                            algorithm = new Algorithm("AES", detectionLocation);
                            cipher =
                                    new AuthenticatedEncryption(
                                            algorithm, null, null, null);
                            cipher.append(new Encrypt(detectionLocation));
                            return Optional.of(cipher);
                        }
                        break;
                }
                break;
            case PADDING:
                if (kind == CipherContext.Kind.OAEP) {
                    padding = new Padding("OAEP", detectionLocation, new HashMap<>());
                    return Optional.of(
                            new OptimalAsymmetricEncryptionPadding(padding));
                }
                break;
            case WRAP:
                // TODO: use `kind` here to know if there is padding or not, and update the
                // translation accordingly
                String algorithmName = "AES";
                Encapsulate encapsulate = new Encapsulate(detectionLocation);
                SecretKey secretKey = new SecretKey(algorithmName, detectionLocation);
                encapsulate.append(secretKey);
                BlockCipher blockCipher =
                        new BlockCipher(
                                new Algorithm(algorithmName, detectionLocation),
                                null,
                                null);
                secretKey.append(blockCipher);
                blockCipher.append(new KeyGeneration(detectionLocation));
                return Optional.of(encapsulate);
            default:
                break;
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateCipherContextKeySize(
            @Nonnull final KeySize<Tree> keySize,
            @Nonnull CipherContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        if (kind == CipherContext.Kind.PKCS7 || kind == CipherContext.Kind.ANSIX923) {
            // Case where the padding has been captured directly as an integer
            return Optional.of(
                    paddingWithBlockSize(kind.name(), keySize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }

    @Nonnull
    private static Padding paddingWithBlockSize(
            @Nonnull String paddingName,
            int blockSize,
            @Nonnull DetectionLocation detectionLocation) {
        Padding padding = new Padding(paddingName, detectionLocation, new HashMap<>());
        padding.append(new BlockSize(blockSize, detectionLocation));
        return padding;
    }
}
