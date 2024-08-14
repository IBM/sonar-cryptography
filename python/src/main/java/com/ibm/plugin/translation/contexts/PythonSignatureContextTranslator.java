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
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.PythonEnricher;
import java.util.HashMap;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PythonSignatureContextTranslator {

    private PythonSignatureContextTranslator() {
        // private
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
