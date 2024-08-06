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
import com.ibm.engine.model.SeedSize;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslationWithKind;
import com.ibm.mapper.mapper.jca.JcaPRNGMapper;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Seed;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaPRNGContextTranslator implements IContextTranslationWithKind<Tree> {

    @NotNull @Override
    public Optional<INode> translate(
            @NotNull IBundle bundleIdentifier,
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (!bundleIdentifier.getIdentifier().equals("Random")) {
            return Optional.empty();
        }

        if (value instanceof SeedSize<Tree> seedSize) {
            JcaPRNGMapper jcaPRNGMapper = new JcaPRNGMapper();
            Optional<? extends IAlgorithm> prngOptional =
                    jcaPRNGMapper.parse("NativePRNG", detectionLocation);
            return prngOptional.map(
                    prng -> {
                        Seed seed = new Seed(seedSize.getValue(), detectionLocation);
                        prng.append(seed);
                        return prng;
                    });
        }
        return Optional.empty();
    }
}
