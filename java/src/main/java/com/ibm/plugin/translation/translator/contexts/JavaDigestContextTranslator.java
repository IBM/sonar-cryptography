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
import com.ibm.mapper.AbstractContextTranslator;
import com.ibm.mapper.IContextTranslationWithKind;
import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.jca.JcaMessageDigestMapper;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaDigestContextTranslator extends AbstractContextTranslator
        implements IContextTranslationWithKind<Tree, DigestContext.Kind> {

    public JavaDigestContextTranslator(@NotNull Configuration configuration) {
        super(configuration);
    }

    @NotNull @Override
    public Optional<INode> translate(
            @NotNull IValue<Tree> value,
            @NotNull DigestContext.Kind kind,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree>) {
            JcaMessageDigestMapper messageDigestMapper = new JcaMessageDigestMapper();
            return messageDigestMapper
                    .parse(value.asString(), detectionLocation, configuration)
                    .map(
                            algo -> {
                                algo.append(new Digest(detectionLocation));
                                return algo;
                            });
        } else if (value instanceof ValueAction) {
            String digestName = value.asString();
            DigestSize digestSize = null;

            // Updating the digest name and size (when necessary)
            switch (digestName) {
                case "GOST3411_2012_256":
                    digestSize = new DigestSize(256, detectionLocation);
                    digestName = "GOST R 34.11-2012";
                    break;
                case "GOST3411_2012_512":
                    digestSize = new DigestSize(512, detectionLocation);
                    digestName = "GOST R 34.11-2012";
                    break;
                case "Haraka256":
                    digestSize = new DigestSize(256, detectionLocation);
                    digestName = "Haraka";
                    break;
                case "Haraka512":
                    digestSize = new DigestSize(512, detectionLocation);
                    digestName = "Haraka";
                    break;
                case "RIPEMD128":
                    digestSize = new DigestSize(128, detectionLocation);
                    digestName = "RIPEMD";
                    break;
                case "RIPEMD160":
                    digestSize = new DigestSize(160, detectionLocation);
                    digestName = "RIPEMD";
                    break;
                case "RIPEMD256":
                    digestSize = new DigestSize(256, detectionLocation);
                    digestName = "RIPEMD";
                    break;
                case "RIPEMD320":
                    digestSize = new DigestSize(320, detectionLocation);
                    digestName = "RIPEMD";
                    break;
                default:
                    break;
            }

            com.ibm.mapper.model.Algorithm algorithm =
                    new com.ibm.mapper.model.Algorithm(digestName, detectionLocation);
            MessageDigest messageDigest;

            switch (kind) {
                case MGF1, MGF:
                    return Optional.of(new MaskGenerationFunction(algorithm, detectionLocation));
                default:
                    if (digestSize != null) {
                        messageDigest = new MessageDigest(algorithm, digestSize, detectionLocation);
                    } else {
                        messageDigest = new MessageDigest(algorithm, detectionLocation);
                    }
                    return Optional.of(messageDigest);
            }
        } else if (value instanceof com.ibm.engine.model.DigestSize) {
            return Optional.of(
                    new DigestSize(Integer.parseInt(value.asString()), detectionLocation));
        }
        return Optional.empty();
    }
}
