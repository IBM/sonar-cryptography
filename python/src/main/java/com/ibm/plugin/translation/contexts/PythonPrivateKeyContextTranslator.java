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

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.PythonTranslatorUtils;
import org.sonar.plugins.python.api.tree.Tree;

import javax.annotation.Nonnull;
import java.util.Optional;

@SuppressWarnings("java:S1301")
public final class PythonPrivateKeyContextTranslator {

    private PythonPrivateKeyContextTranslator() {
        // private
    }

    @Nonnull
    public static Optional<INode> translateForPrivateKeyContext(
            @Nonnull final IValue<Tree> value,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm) {
            return translatePrivateKeyContextAlgorithm(detectedAlgorithm, kind, detectionLocation);
        } else if (value instanceof KeySize<Tree> keySize) {
            return translatePrivateKeyContextKeySize(keySize, kind, detectionLocation);
        } else if (value instanceof KeyAction<Tree> keyAction) {
            return translatePrivateKeyContextKeyAction(keyAction, kind, detectionLocation);
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translatePrivateKeyContextAlgorithm(
            @Nonnull final com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        switch (kind) {
            case EC:
                // General rule for algorithms detected in this context: we consider that it is
                // an EC algorithm used for key generation, and that the created structure
                // contains a reference to a private and a public key
                return Optional.of(
                        PythonTranslatorUtils.generateEcPrivateKeyTranslation(
                                "EC", detectedAlgorithm.asString(), detectionLocation));
            default:
                break;
        }

        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translatePrivateKeyContextKeySize(
            @Nonnull final KeySize<Tree> keySize,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        switch (kind) {
            case RSA:
                return Optional.of(
                        PythonTranslatorUtils.generatePrivateKeyWithAlgorithm(
                                "RSA", Optional.of(keySize.getValue()), detectionLocation));
            case DSA:
                return Optional.of(
                        PythonTranslatorUtils.generatePrivateKeyWithAlgorithm(
                                "DSA", Optional.of(keySize.getValue()), detectionLocation));
            default:
                break;
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translatePrivateKeyContextKeyAction(
            @Nonnull final KeyAction<Tree> keyAction,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        Signature signature;
        PrivateKey privateKey;
        String algorithmName;
        switch (keyAction.getAction()) {
            case GENERATION:
                switch (kind) {
                    case Fernet:
                        return Optional.of(
                                PythonTranslatorUtils.generateOnlyPrivateKeyTranslation(
                                        "Fernet", detectionLocation));
                    case RSA:
                        return Optional.of(
                                PythonTranslatorUtils.generateOnlyPrivateKeyTranslation(
                                        "RSA", detectionLocation));
                    case DSA:
                        return Optional.of(
                                PythonTranslatorUtils.generateOnlyPrivateKeyTranslation(
                                        "DSA", detectionLocation));
                    case DH:
                        return Optional.of(
                                PythonTranslatorUtils.generateOnlyPrivateKeyTranslation(
                                        "DH", detectionLocation));
                    case DH_FULL:
                        return Optional.of(
                                PythonTranslatorUtils.generatePrivateKeyWithAlgorithm(
                                        "DH", Optional.empty(), detectionLocation));
                    case X25519:
                        // TODO: Translate ECDH as a protocol here
                        return Optional.of(
                                PythonTranslatorUtils.generateEcPrivateKeyTranslation(
                                        "EC", "Curve25519", detectionLocation));
                    case X448:
                        // TODO: Translate ECDH as a protocol here
                        return Optional.of(
                                PythonTranslatorUtils.generateEcPrivateKeyTranslation(
                                        "EC", "Curve448", detectionLocation));
                    case Ed25519:
                        privateKey =
                                PythonTranslatorUtils.generateEcPrivateKeyTranslation(
                                        "EC", "Curve25519", detectionLocation);
                        signature =
                                new Signature(
                                        new Algorithm("EdDSA", detectionLocation));
                        signature.append(
                                new MessageDigest(
                                        new Algorithm("SHA512", detectionLocation))); // According to Wikipedia
                        // (https://en.wikipedia.org/wiki/EdDSA#Ed25519)
                        signature.append(new Sign(detectionLocation));
                        privateKey.append(signature);
                        // TODO: Should I have `Ed25519` appear somewhere?
                        return Optional.of(privateKey);
                    case Ed448:
                        privateKey =
                                PythonTranslatorUtils.generateEcPrivateKeyTranslation(
                                        "EC", "Curve448", detectionLocation);
                        signature =
                                new Signature(
                                        new Algorithm("EdDSA", detectionLocation));
                        signature.append(
                                new MessageDigest(
                                        new Algorithm("SHA512", detectionLocation))); // According to Wikipedia
                        // (https://en.wikipedia.org/wiki/EdDSA#Ed25519)
                        signature.append(new Sign(detectionLocation));
                        privateKey.append(signature);
                        // TODO: Should I have `Ed25519` appear somewhere?
                        return Optional.of(privateKey);
                    case EC:
                        // Case happening for `EllipticCurvePrivateNumbers`
                        algorithmName = "EC";
                        privateKey = new PrivateKey(algorithmName, detectionLocation);
                        return Optional.of(privateKey);
                    default:
                        break;
                }
                break;
            default:
                break;
        }
        return Optional.empty();
    }
}
