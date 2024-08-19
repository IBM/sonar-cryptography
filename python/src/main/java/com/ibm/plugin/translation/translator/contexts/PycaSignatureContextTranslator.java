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
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.MGF1;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.python.api.tree.Tree;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.Optional;

@SuppressWarnings("java:S1301")
public final class PycaSignatureContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @NotNull Optional<INode> translate(@NotNull IBundle bundleIdentifier,
                                              @NotNull IValue<Tree> value,
                                              @NotNull IDetectionContext detectionContext,
                                              @NotNull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree> algorithm) {
            return switch (algorithm.asString().toUpperCase().trim()) {
                case "EC" -> Optional.of(new EllipticCurveAlgorithm(Signature.class, new EllipticCurveAlgorithm(detectionLocation)));
                case "ECDSA" -> Optional.of(new ECDSA(detectionLocation));
                case "MGF1" -> Optional.of(new MGF1(detectionLocation)); // TODO: to verify
                default -> Optional.empty();
            };
        } else if (value instanceof SignatureAction<Tree> signatureAction) {
            return switch (signatureAction.getAction()) {
                case SIGN -> Optional.of(new Sign(detectionLocation));
                case VERIFY -> Optional.of(new Verify(detectionLocation));
            };
        } else if (value instanceof ValueAction<Tree>) {
            if (detectionContext instanceof DetectionContext context) {
                context.get("padding")
            }
        }
        return Optional.empty();
    }

    @Nonnull
    public static Optional<INode> translateForSignatureContext(
            @Nonnull final IValue<Tree> value,
            @Nonnull SignatureContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm) {
            return translateSignatureContextAlgorithm(detectedAlgorithm, kind, detectionLocation);
        } else if (value instanceof SignatureAction<Tree> signatureAction) {
            return translateSignatureContextSignatureAction(
                    signatureAction, kind, detectionLocation);
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateSignatureContextAlgorithm(
            @Nonnull final com.ibm.engine.model.Algorithm<Tree> detectedAlgorithm,
            @Nonnull SignatureContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        Algorithm baseAlgorithm;
        Algorithm resAlgorithm;
        switch (detectedAlgorithm.asString()) {
            case "ECDSA":
                baseAlgorithm = new Algorithm("ECDSA", detectionLocation);
                resAlgorithm = new Signature(baseAlgorithm);
                return Optional.of(resAlgorithm);
            case "MGF1":
                return Optional.of(
                        new MaskGenerationFunction(new Algorithm("MGF1", detectionLocation)));
            default:
                break;
        }
        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateSignatureContextSignatureAction(
            @Nonnull final SignatureAction<Tree> signatureAction,
            @Nonnull SignatureContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        Algorithm baseAlgorithm;
        Algorithm resAlgorithm;
        switch (signatureAction.getAction()) {
            case SIGN:
                baseAlgorithm = new Algorithm(PythonEnricher.TO_BE_ENRICHED, detectionLocation);
                resAlgorithm = new Signature(baseAlgorithm);
                resAlgorithm.put(new Sign(detectionLocation));
                return Optional.of(resAlgorithm);
            case VERIFY:
            // TODO: Handle this case
            case PADDING:
                switch (kind) {
                    case PSS:
                        return Optional.of(new ProbabilisticSignatureScheme(detectionLocation));
                    case PKCS1v15:
                        return Optional.of(
                                new Padding("PKCS1v15", detectionLocation, new HashMap<>()));
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
