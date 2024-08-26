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

import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.python.api.tree.Tree;

public class PycaKeyAgreementContextTranslator implements IContextTranslation<Tree> {
    @Override
    public @NotNull Optional<INode> translate(
            @NotNull IBundle bundleIdentifier,
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree> algorithm) {
            return switch (algorithm.asString().toUpperCase().trim()) {
                case "ECDH" -> Optional.of(new ECDH(detectionLocation));
                case "EC" ->
                        Optional.of(
                                new EllipticCurveAlgorithm(
                                        KeyAgreement.class,
                                        new EllipticCurveAlgorithm(detectionLocation)));
                default -> Optional.empty();
            };
        } else if (value instanceof KeyAction<Tree>) {
            // key action is always "generate"
            if (detectionContext instanceof DetectionContext context) {
                return context.get("algorithm")
                        .map(
                                algo ->
                                        switch (algo.toUpperCase().trim()) {
                                            case "X25519" -> new X25519(detectionLocation);
                                            case "X448" -> new X448(detectionLocation);
                                            default -> null;
                                        });
            }
        }
        return Optional.empty();
    }
}
