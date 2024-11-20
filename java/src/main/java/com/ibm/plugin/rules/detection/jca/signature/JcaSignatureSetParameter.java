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
package com.ibm.plugin.rules.detection.jca.signature;

import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.jca.algorithmspec.JcaAlgorithmParameterSpec;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JcaSignatureSetParameter {

    private static final IDetectionRule<Tree> SIGNATURE_SET_PARAMETER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.Signature")
                    .forMethods("setParameter")
                    .withMethodParameter("java.security.spec.AlgorithmParameterSpec")
                    .addDependingDetectionRules(JcaAlgorithmParameterSpec.rules())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private JcaSignatureSetParameter() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(SIGNATURE_SET_PARAMETER);
    }
}
