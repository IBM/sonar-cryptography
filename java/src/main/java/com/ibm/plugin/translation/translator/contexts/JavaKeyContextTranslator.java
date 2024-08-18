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
import com.ibm.mapper.mapper.jca.JcaAlgorithmMapper;
import com.ibm.mapper.mapper.jca.JcaCurveMapper;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaKeyContextTranslator extends JavaAbstractLibraryTranslator {

    @Override
    protected @NotNull Optional<INode> translateJCA(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree> algorithm) {
            JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
            return jcaAlgorithmMapper
                    .parse(algorithm.asString(), detectionLocation)
                    .map(
                            algo -> {
                                // key gen
                                algo.put(new KeyGeneration(detectionLocation));
                                // put key
                                final Key key = new Key((IAlgorithm) algo);
                                if (detectionContext.is(PrivateKeyContext.class)) {
                                    return new PrivateKey(key);
                                } else if (detectionContext.is(PublicKeyContext.class)) {
                                    return new PublicKey(key);
                                } else if (detectionContext.is(SecretKeyContext.class)) {
                                    return new SecretKey(key);
                                }
                                return key;
                            });
        } else if (value instanceof KeySize<Tree> keySize) {
            final KeyLength keyLength = new KeyLength(keySize.getValue(), detectionLocation);
            return Optional.of(keyLength);
        } else if (value instanceof Curve<Tree> curve) {
            final JcaCurveMapper jcaCurveMapper = new JcaCurveMapper();
            return jcaCurveMapper
                    .parse(curve.asString(), detectionLocation)
                    .map(
                            algo -> {
                                // key gen
                                algo.put(new KeyGeneration(detectionLocation));
                                return algo;
                            });
        }
        return Optional.empty();
    }

    @Override
    protected @NotNull Optional<INode> translateBC(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof ValueAction<Tree> valueAction) {
            final KeyContext.Kind kind = ((SecretKeyContext) detectionContext).kind();
            com.ibm.mapper.model.Algorithm algorithm;
            switch (kind) {
                /*case KDF:
                    algorithm =
                            new com.ibm.mapper.model.Algorithm(
                                    valueAction.asString(), detectionLocation);
                    if (valueAction.asString().equals("MGF1")) {
                        return Optional.of(new MaskGenerationFunction(algorithm));
                    }
                    return Optional.of(new KeyDerivationFunction(algorithm));
                case KEM:
                    algorithm =
                            new com.ibm.mapper.model.Algorithm(
                                    valueAction.asString(), detectionLocation);
                    return Optional.of(new KeyEncapsulationMechanism(algorithm));*/
                default:
                    break;
            }
        }
        return Optional.empty();
    }
}
