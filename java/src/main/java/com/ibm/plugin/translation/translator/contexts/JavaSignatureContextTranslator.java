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
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.AbstractContextTranslator;
import com.ibm.mapper.IContextTranslationWithKind;
import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.bc.BcOperationModeSigningMapper;
import com.ibm.mapper.mapper.jca.JcaAlgorithmMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.translator.JavaTranslator;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaSignatureContextTranslator extends AbstractContextTranslator
        implements IContextTranslationWithKind<Tree, SignatureContext.Kind> {

    public JavaSignatureContextTranslator(@NotNull Configuration configuration) {
        super(configuration);
    }

    @NotNull @Override
    public Optional<INode> translate(
            @NotNull IValue<Tree> value,
            @NotNull SignatureContext.Kind kind,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree>) {
            final JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
            return jcaAlgorithmMapper
                    .parse(value.asString(), detectionLocation, configuration)
                    .map(a -> a);
        } else if (value instanceof SignatureAction<Tree> signatureAction) {
            return switch (signatureAction.getAction()) {
                case SIGN -> Optional.of(new Sign(detectionLocation));
                case VERIFY -> Optional.of(new Verify(detectionLocation));
                case PADDING -> Optional.empty(); // TODO: handle
            };
        } else if (value instanceof OperationMode<Tree> operationMode) {
            switch (kind) {
                case SIGNING_STATUS:
                    BcOperationModeSigningMapper bcOperationModeSigningMapper =
                            new BcOperationModeSigningMapper();
                    return bcOperationModeSigningMapper
                            .parse(operationMode.asString(), detectionLocation, configuration)
                            .map(f -> f);
                default:
                    break;
            }
        } else if (value instanceof ValueAction<Tree> valueAction) {
            // TODO: Write a mapper
            Algorithm algorithm;
            Signature signature;
            EllipticCurveAlgorithm eca;
            ProbabilisticSignatureScheme pss;
            switch (kind) {
                case EdDSA:
                    String curveName = JavaTranslator.UNKNOWN;
                    switch (valueAction.asString()) {
                        case "Ed25519":
                            curveName = "Curve25519";
                            break;
                        case "Ed448":
                            curveName = "Curve448";
                            break;
                        default:
                            break;
                    }
                    algorithm = new Algorithm("EdDSA", detectionLocation);
                    signature = new Signature(algorithm, detectionLocation);

                    eca =
                            new EllipticCurveAlgorithm(
                                    new Algorithm("EC", detectionLocation), detectionLocation);
                    eca.append(new EllipticCurve(curveName, detectionLocation));

                    signature.append(eca);
                    return Optional.of(signature);
                case ALGORITHM_AND_HASH_WRAPPER, DIGEST_MESSAGE_WRAPPER:
                    /* TODO: Choose a better way to translate DIGEST_MESSAGE_WRAPPER */
                    algorithm = new Algorithm(JavaTranslator.UNKNOWN, detectionLocation);
                    signature = new Signature(algorithm, detectionLocation);
                    return Optional.of(signature);
                case RSA:
                    algorithm =
                            new Algorithm(JavaTranslator.UNKNOWN + "withRSA", detectionLocation);
                    signature = new Signature(algorithm, detectionLocation);
                    PublicKeyEncryption pke =
                            new PublicKeyEncryption(
                                    new Algorithm("RSA", detectionLocation), detectionLocation);
                    signature.append(pke);
                    return Optional.of(signature);
                case SIGNATURE_NAME, DSA:
                    algorithm = new Algorithm(valueAction.asString(), detectionLocation);
                    signature = new Signature(algorithm, detectionLocation);
                    return Optional.of(signature);
                case PSS:
                    pss = new ProbabilisticSignatureScheme(detectionLocation);
                    algorithm = new Algorithm(JavaTranslator.UNKNOWN + "-PSS", detectionLocation);
                    signature = new Signature(algorithm, detectionLocation);
                    signature.append(pss);
                    return Optional.of(signature);
                default:
                    // TODO: temporary translation that shouldn't be used
                    algorithm = new Algorithm(valueAction.asString(), detectionLocation);
                    return Optional.of(algorithm);
            }
        }
        return Optional.empty();
    }
}
