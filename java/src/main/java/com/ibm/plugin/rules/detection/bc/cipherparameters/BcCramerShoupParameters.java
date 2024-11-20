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
package com.ibm.plugin.rules.detection.bc.cipherparameters;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BIGINTEGER_TYPE;

import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.bc.digest.BcDigests;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcCramerShoupParameters {

    private BcCramerShoupParameters() {
        // nothing
    }

    /*
     * This base constructor is the only rule where we have to specify the context.
     */
    private static final IDetectionRule<Tree> BASE_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.params.CramerShoupParameters")
                    .forConstructor()
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter("org.bouncycastle.crypto.Digest")
                    .addDependingDetectionRules(BcDigests.rules())
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_KEY_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.bouncycastle.crypto.params.CramerShoupPrivateKeyParameters")
                    .forConstructor()
                    .withMethodParameter("org.bouncycastle.crypto.params.CramerShoupParameters")
                    .addDependingDetectionRules(List.of(BASE_CONSTRUCTOR))
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PUBLIC_KEY_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.params.CramerShoupPublicKeyParameters")
                    .forConstructor()
                    .withMethodParameter("org.bouncycastle.crypto.params.CramerShoupParameters")
                    .addDependingDetectionRules(List.of(BASE_CONSTRUCTOR))
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(BASE_CONSTRUCTOR, PRIVATE_KEY_CONSTRUCTOR, PUBLIC_KEY_CONSTRUCTOR);
    }
}
