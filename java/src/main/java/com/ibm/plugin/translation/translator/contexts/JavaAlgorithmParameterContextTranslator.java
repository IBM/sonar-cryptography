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
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.MacSize;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.jca.JcaAlgorithmMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

import java.util.Optional;

public final class JavaAlgorithmParameterContextTranslator extends AbstractJavaTranslator {

    public JavaAlgorithmParameterContextTranslator(@NotNull Configuration configuration) {
        super(configuration);
    }

    @Override
    protected @NotNull Optional<INode> translateJCA(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree>) {
            JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
            return jcaAlgorithmMapper
                    .parse(value.asString(), detectionLocation, configuration)
                    .map(a -> a);
        } else if (value instanceof KeySize<Tree> keySize) {
            KeyLength keyLength = new KeyLength(keySize.getValue(), detectionLocation);
            return Optional.of(keyLength);
        } else if (value instanceof MacSize<Tree> macSize) {
            TagLength tagLength = new TagLength(macSize.getValue(), detectionLocation);
            return Optional.of(tagLength);
        }
        return Optional.empty();
    }

    @Override
    protected @NotNull Optional<INode> translateBC(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        return Optional.empty();
    }
}
