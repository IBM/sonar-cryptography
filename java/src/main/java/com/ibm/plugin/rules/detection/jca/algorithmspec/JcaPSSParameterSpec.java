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
package com.ibm.plugin.rules.detection.jca.algorithmspec;

import static com.ibm.plugin.rules.detection.TypeShortcuts.STRING_TYPE;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.SaltSizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

// https://docs.oracle.com/javase/8/docs/api/java/security/spec/PSSParameterSpec.html
public final class JcaPSSParameterSpec {

    private static final IDetectionRule<Tree> PSS_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.spec.PSSParameterSpec")
                    .forConstructor()
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .buildForContext(new SignatureContext(SignatureContext.Kind.PSS))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PSS_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.spec.PSSParameterSpec")
                    .forConstructor()
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>()) // id 0
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>()) // id 1
                    .withMethodParameter("java.security.spec.AlgorithmParameterSpec")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(1)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .withMethodParameter("int")
                    .buildForContext(new SignatureContext(SignatureContext.Kind.PSS))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private JcaPSSParameterSpec() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(PSS_1, PSS_2);
    }
}
