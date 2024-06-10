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
package com.ibm.plugin.rules.detection.jca.keyspec;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BIGINTEGER_TYPE;

import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.jca.algorithmspec.JcaECGenParameterSpec;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class JcaECPrivateKeySpec {

    private static final IDetectionRule<Tree> EC_PRIVATE_KEY_SPEC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.spec.ECPrivateKeySpec")
                    .forConstructor()
                    .withMethodParameter(BIGINTEGER_TYPE) // the private value
                    .withMethodParameter("java.security.spec.ECParameterSpec")
                    .addDependingDetectionRules(JcaECGenParameterSpec.rules())
                    .buildForContext(new KeyContext(KeyContext.Kind.EC))
                    .inBundle(() -> "JcaECPrivateKeySpec")
                    .withoutDependingDetectionRules();

    private JcaECPrivateKeySpec() {
        // nothing
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(EC_PRIVATE_KEY_SPEC);
    }
}
