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

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.PythonTranslatorUtils;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PythonSecretKeyContextTranslator {

    private PythonSecretKeyContextTranslator() {
        // private
    }

    @Nonnull
    public static Optional<INode> translateForSecretKeyContext(
            @Nonnull final IValue<Tree> value,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm) {
            return translateSecretKeyContextAlgorithm(detectedAlgorithm, kind, detectionLocation);
        } else if (value instanceof KeySize<Tree> keySize) {
            return translateSecretKeyContextKeySize(keySize, kind, detectionLocation);
        } else if (value instanceof KeyAction<Tree> keyAction) {
            return translateSecretKeyContextKeyAction(keyAction, kind, detectionLocation);
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateSecretKeyContextAlgorithm(
            @Nonnull final com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        switch (detectedAlgorithm.asString()) {
            case "ECDH":
                // TODO: Translate ECDH as a protocol here
                return Optional.empty();
            default:
                break;
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateSecretKeyContextKeySize(
            @Nonnull final KeySize<Tree> keySize,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        switch (kind) {
            default:
                if (kind.name().startsWith("AES")) {
                    // Cases "AESGCM", "AESGCMIV", "AESOCB3", "AESSIV", "AESCCM"
                    return Optional.of(
                            PythonTranslatorUtils.generateSecretKeyWithAES(
                                    kind.name(), keySize.getValue(), detectionLocation));
                }
                break;
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateSecretKeyContextKeyAction(
            @Nonnull final KeyAction<Tree> keyAction,
            @Nonnull KeyContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        if (keyAction.getAction() == KeyAction.Action.GENERATION
                && (kind == KeyContext.Kind.CHACHA20POLY1305)) {
            String cipherString = "ChaCha20";
            String macString = "Poly1305";
            SecretKey secretKey = new SecretKey(cipherString, detectionLocation);
            StreamCipher cipher =
                    PythonTranslatorUtils.generateNewStreamCipher(
                            cipherString, macString, detectionLocation);
            cipher.put(new KeyGeneration(detectionLocation));
            secretKey.put(cipher);
            return Optional.of(secretKey);
        }

        return Optional.empty();
    }
}
