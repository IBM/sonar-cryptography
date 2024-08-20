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
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PycaPrivateKeyContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @NotNull Optional<INode> translate(
            @NotNull IBundle bundleIdentifier,
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof KeyAction<Tree>
                && detectionContext instanceof DetectionContext context) {
            return context.get("algorithm")
                    .map(
                            algorithm ->
                                    switch (algorithm.toUpperCase().trim()) {
                                        case "DH" -> new DH(detectionLocation);
                                        case "FERNET" -> null; // TODO
                                        case "RSA" -> new RSA(detectionLocation);
                                        case "DSA" -> new DSA(detectionLocation);
                                        case "EC" -> new EllipticCurveAlgorithm(detectionLocation);
                                        case "ED25519" -> new Ed25519(detectionLocation);
                                        case "ED448" -> new Ed448(detectionLocation);
                                        default -> null;
                                    })
                    .map(
                            algorithm -> {
                                PrivateKey privateKey = new PrivateKey(algorithm);
                                privateKey.put(
                                        new Generate(
                                                detectionLocation)); // currently only GENERATE is
                                // used as key action is this
                                // context
                                return privateKey;
                            });
        } else if (value instanceof KeySize<Tree> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }
}
