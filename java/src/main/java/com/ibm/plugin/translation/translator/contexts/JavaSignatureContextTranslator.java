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
import com.ibm.mapper.ITranslator;
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
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaSignatureContextTranslator extends JavaAbstractLibraryTranslator {

    @Override
    protected @NotNull Optional<INode> translateJCA(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree>) {
            final JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
            return jcaAlgorithmMapper.parse(value.asString(), detectionLocation).map(a -> a);
        } else if (value instanceof SignatureAction<Tree> signatureAction) {
            return switch (signatureAction.getAction()) {
                case SIGN -> Optional.of(new Sign(detectionLocation));
                case VERIFY -> Optional.of(new Verify(detectionLocation));
                case PADDING -> Optional.empty();
            };
        }
        return Optional.empty();
    }

    @Override
    protected @NotNull Optional<INode> translateBC(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        final SignatureContext.Kind kind = ((SignatureContext) detectionContext).kind();
        if (value instanceof ValueAction<Tree> valueAction) {
            Algorithm algorithm;
            Signature signature;
            EllipticCurveAlgorithm eca;
            ProbabilisticSignatureScheme pss;
            switch (kind) {
                case EdDSA:
                    String curveName = ITranslator.UNKNOWN;
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
                    signature = new Signature(algorithm);

                    eca = new EllipticCurveAlgorithm(new Algorithm("EC", detectionLocation));
                    eca.append(new EllipticCurve(curveName, detectionLocation));

                    signature.append(eca);
                    return Optional.of(signature);
                case ALGORITHM_AND_HASH_WRAPPER, DIGEST_MESSAGE_WRAPPER:
                    // Maybe choose a better way to translate DIGEST_MESSAGE_WRAPPER
                    algorithm = new Algorithm(ITranslator.UNKNOWN, detectionLocation);
                    signature = new Signature(algorithm);
                    return Optional.of(signature);
                case RSA:
                    algorithm = new Algorithm(ITranslator.UNKNOWN + "withRSA", detectionLocation);
                    signature = new Signature(algorithm);
                    PublicKeyEncryption pke =
                            new PublicKeyEncryption(new Algorithm("RSA", detectionLocation));
                    signature.append(pke);
                    return Optional.of(signature);
                case SIGNATURE_NAME, DSA:
                    algorithm = new Algorithm(valueAction.asString(), detectionLocation);
                    signature = new Signature(algorithm);
                    return Optional.of(signature);
                case PSS:
                    pss = new ProbabilisticSignatureScheme(detectionLocation);
                    algorithm = new Algorithm(ITranslator.UNKNOWN + "-PSS", detectionLocation);
                    signature = new Signature(algorithm);
                    signature.append(pss);
                    return Optional.of(signature);
                default:
                    algorithm = new Algorithm(valueAction.asString(), detectionLocation);
                    return Optional.of(algorithm);
            }
        } else if (value instanceof OperationMode<Tree> operationMode) {
            switch (kind) {
                case SIGNING_STATUS:
                    BcOperationModeSigningMapper bcOperationModeSigningMapper =
                            new BcOperationModeSigningMapper();
                    return bcOperationModeSigningMapper
                            .parse(operationMode.asString(), detectionLocation)
                            .map(f -> f);
                default:
                    break;
            }
        }
        return Optional.empty();
    }
}
