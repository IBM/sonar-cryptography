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
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.AbstractContextTranslator;
import com.ibm.mapper.IContextTranslationWithKind;
import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.jca.JcaAlgorithmMapper;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import java.util.stream.Stream;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaKeyContextTranslator extends AbstractContextTranslator
        implements IContextTranslationWithKind<Tree, KeyContext.Kind> {

    public JavaKeyContextTranslator(@NotNull Configuration configuration) {
        super(configuration);
    }

    @SuppressWarnings("java:S1172")
    @NotNull @Override
    public Optional<INode> translate(
            @NotNull IValue<Tree> value,
            @NotNull KeyContext.Kind kind,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree> algorithm) {
            JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
            return jcaAlgorithmMapper
                    .parse(algorithm.asString(), detectionLocation, configuration)
                    .map(iNode -> (com.ibm.mapper.model.Algorithm) iNode)
                    .map(
                            algorithmNode ->
                                    switch (algorithmNode.asString().trim().toLowerCase()) {
                                        case "rsa" ->
                                                new PublicKeyEncryption(
                                                        algorithmNode,
                                                        algorithmNode.getDetectionContext());
                                        case "diffiehellman" ->
                                                new KeyAgreement(
                                                        algorithmNode,
                                                        algorithmNode.getDetectionContext());
                                        default -> algorithmNode;
                                    })
                    .map(
                            algorithmNode -> {
                                algorithmNode.append(new KeyGeneration(detectionLocation));
                                return algorithmNode;
                            })
                    .map(
                            algorithmNode -> {
                                final Key key =
                                        new Key(
                                                algorithmNode.asString(),
                                                algorithmNode,
                                                detectionLocation);
                                if (detectionContext.is(PrivateKeyContext.class)) {
                                    return new PrivateKey(key, key.getDetectionContext());
                                } else if (detectionContext.is(PublicKeyContext.class)) {
                                    return new PublicKey(key, key.getDetectionContext());
                                } else if (detectionContext.is(SecretKeyContext.class)) {
                                    return new SecretKey(key, key.getDetectionContext());
                                } else {
                                    return switch (algorithmNode.asString().trim().toLowerCase()) {
                                        case "rsa" -> new PublicKey(key, key.getDetectionContext());
                                        default -> algorithmNode;
                                    };
                                }
                            });
        } else if (value instanceof KeySize<Tree> keySize) {
            KeyLength keyLength = new KeyLength(keySize.getValue(), detectionLocation);
            return Optional.of(keyLength);
        } else if (value instanceof Curve<Tree> curve) {
            com.ibm.mapper.model.Algorithm algorithm =
                    new com.ibm.mapper.model.Algorithm("EC", detectionLocation);
            return Stream.of(algorithm)
                    .map(algo -> new EllipticCurveAlgorithm(algo, detectionLocation))
                    .map(
                            algo -> {
                                algo.append(new KeyGeneration(detectionLocation));
                                algo.append(new EllipticCurve(curve.asString(), detectionLocation));
                                return algo;
                            })
                    .findFirst()
                    .map(a -> a);
        } else if (value instanceof ValueAction<Tree> valueAction) {
            com.ibm.mapper.model.Algorithm algorithm;
            switch (kind) {
                case KDF:
                    algorithm =
                            new com.ibm.mapper.model.Algorithm(
                                    valueAction.asString(), detectionLocation);
                    if (valueAction.asString().equals("MGF1")) {
                        return Optional.of(
                                new MaskGenerationFunction(algorithm, detectionLocation));
                    }
                    return Optional.of(new KeyDerivationFunction(algorithm, detectionLocation));
                case KEM:
                    algorithm =
                            new com.ibm.mapper.model.Algorithm(
                                    valueAction.asString(), detectionLocation);
                    return Optional.of(new KeyEncapsulationMechanism(algorithm, detectionLocation));
                default:
                    break;
            }
        }
        return Optional.empty();
    }
}
