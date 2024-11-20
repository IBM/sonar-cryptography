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
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PycaPublicKeyContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof KeyAction<Tree>
                && detectionContext instanceof DetectionContext context) {
            return context.get("algorithm")
                    .map(
                            algorithm ->
                                    switch (algorithm.toUpperCase().trim()) {
                                        case "DH" -> new DH(detectionLocation);
                                        case "RSA" -> new RSA(detectionLocation);
                                        case "DSA" -> new DSA(detectionLocation);
                                        default -> null;
                                    })
                    .map(
                            algorithm -> {
                                PublicKey publicKey = new PublicKey(algorithm);
                                publicKey.put(
                                        new KeyGeneration(
                                                detectionLocation)); // currently only GENERATE is
                                // used as key action is this
                                // context
                                return publicKey;
                            });
        }
        return Optional.empty();
    }
}
