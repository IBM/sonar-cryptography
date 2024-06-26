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
package com.ibm.plugin.rules.detection.mac;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class CryptographyMAC {

    private CryptographyMAC() {
        // private
    }

    private static final IDetectionRule<Tree> NEW_CMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.cmac")
                    .forMethods("CMAC")
                    .withMethodParameter("cryptography.hazmat.primitives.ciphers.algorithms.*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new MacContext(MacContext.Kind.CMAC))
                    .inBundle(() -> "CryptographyMAC")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> NEW_HMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.hmac")
                    .forMethods("HMAC")
                    .withMethodParameter(ANY)
                    .withMethodParameter(
                            "cryptography.hazmat.primitives.hashes.*") // Accepts only hashes (not
                    // pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new MacContext(MacContext.Kind.HMAC))
                    .inBundle(() -> "CryptographyMAC")
                    .withoutDependingDetectionRules();

    // TODO: Here, the hash is simply detected with a `AlgorithmFactory()`, and then the check of
    //  whether it is an acceptable value is done in the translation. I should probably do it like
    //  this in RSA/DSA/EC. Challenge: they also can use a `Preshashed` containing a hash. In this
    //  case, one should create two duplicate rules (one capturing an immediate hash with
    //  `AlgorithmFactory()`) and the other a `Prehashed`.

    private static final IDetectionRule<Tree> NEW_POLY1305 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.poly1305")
                    .forMethods("Poly1305")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.MAC))
                    .withAnyParameters()
                    .buildForContext(new MacContext(MacContext.Kind.Poly1305))
                    .inBundle(() -> "CryptographyMAC")
                    .withoutDependingDetectionRules();

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW_CMAC, NEW_HMAC, NEW_POLY1305);
    }
}
