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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.mapper.mapper.bc.BcDigestMapper;
import com.ibm.mapper.mapper.jca.JcaMessageDigestMapper;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaDigestContextTranslator extends JavaAbstractLibraryTranslator {

    @Override
    protected @NotNull Optional<INode> translateJCA(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree>) {
            JcaMessageDigestMapper messageDigestMapper = new JcaMessageDigestMapper();
            return messageDigestMapper
                    .parse(value.asString(), detectionLocation)
                    .map(
                            algo -> {
                                algo.put(new Digest(detectionLocation));
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
        final DigestContext.Kind kind = ((DigestContext) detectionContext).kind();
        if (value instanceof ValueAction) {
            switch (kind) {
                case MGF1, MGF -> Optional.empty(); /* TODO: */
                default -> {
                    BcDigestMapper bcDigestsMapper = new BcDigestMapper();
                    return bcDigestsMapper.parse(value.asString(), detectionLocation).map(f -> f);
                }
            }

            /*final com.ibm.mapper.model.Algorithm algorithm =
                    new com.ibm.mapper.model.Algorithm(digestName, detectionLocation);

            final DigestContext.Kind kind = ((DigestContext) detectionContext).kind();
            return switch (kind) {
                case MGF1, MGF -> Optional.of(new MaskGenerationFunction(algorithm));
                default ->
                        Optional.of(
                                Optional.ofNullable(digestSize)
                                        .map(size -> new MessageDigest(algorithm, size))
                                        .orElse(new MessageDigest(algorithm)));
            };*/
        } else if (value instanceof com.ibm.engine.model.DigestSize digestSize) {
            return Optional.of(new DigestSize(digestSize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }
}
