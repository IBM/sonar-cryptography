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

import com.ibm.engine.model.*;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.AbstractContextTranslator;
import com.ibm.mapper.IContextTranslationWithKind;
import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.jca.JcaAlgorithmMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaSecretKeyContextTranslator extends AbstractContextTranslator
        implements IContextTranslationWithKind<Tree, KeyContext.Kind> {

    public JavaSecretKeyContextTranslator(@NotNull Configuration configuration) {
        super(configuration);
    }

    /**
     * Translates the value into the secret key context.
     *
     * @param value The value to translate.
     * @return An optional containing an INode related to the SecretKey value or an empty Optional
     *     if the translation is not possible
     */
    @NotNull @Override
    public Optional<INode> translate(
            @NotNull IValue<Tree> value,
            @NotNull KeyContext.Kind kind,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree> algorithm) {
            JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
            return jcaAlgorithmMapper
                    .parse(algorithm.asString(), detectionLocation, this.configuration)
                    .map(com.ibm.mapper.model.Algorithm.class::cast)
                    .map(
                            algo -> {
                                algo.append(new KeyGeneration(detectionLocation));
                                return algo;
                            })
                    .map(algo -> new Key(algo.asString(), algo, detectionLocation))
                    .map(key -> new SecretKey(key, detectionLocation));
        } else if (value instanceof KeySize<Tree> keySize) {
            KeyLength keyLength = new KeyLength(keySize.getValue(), detectionLocation);
            return Optional.of(keyLength);
        } else if (value instanceof PasswordSize<Tree> passwordSize) {
            return Optional.of(new PasswordLength(passwordSize.getValue(), detectionLocation));
        } else if (value instanceof SaltSize<Tree> saltSize) {
            return Optional.of(new SaltLength(saltSize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }
}
