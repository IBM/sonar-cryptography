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
package com.ibm.plugin.rules.detection.bc.aeadcipher;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.bc.blockcipher.BcBlockCipher;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcGCMBlockCipher {

    private BcGCMBlockCipher() {
        // nothing
    }

    private static final String MODE = "GCMBlockCipher";

    private static final IDetectionRule<Tree> NEW_INSTANCE_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.modes." + MODE)
                    .forMethods("newInstance")
                    .shouldBeDetectedAs(new ValueActionFactory<>(MODE))
                    .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                    .addDependingDetectionRules(
                            BcBlockCipher.all(
                                    new CipherContext(
                                            Map.of("kind", "BLOCK_CIPHER_ENGINE_FOR_AEAD"))))
                    .buildForContext(new CipherContext(Map.of("kind", "AEAD_BLOCK_CIPHER")))
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(BcAEADCipherInit.rules());

    private static final IDetectionRule<Tree> NEW_INSTANCE_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.modes." + MODE)
                    .forMethods("newInstance")
                    .shouldBeDetectedAs(new ValueActionFactory<>(MODE))
                    .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                    .addDependingDetectionRules(
                            BcBlockCipher.all(
                                    new CipherContext(
                                            Map.of("kind", "BLOCK_CIPHER_ENGINE_FOR_AEAD"))))
                    .withMethodParameter("org.bouncycastle.crypto.modes.gcm.GCMMultiplier")
                    .buildForContext(new CipherContext(Map.of("kind", "AEAD_BLOCK_CIPHER")))
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(BcAEADCipherInit.rules());

    private static final IDetectionRule<Tree> CONSTRUCTOR_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.modes." + MODE)
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>(MODE))
                    .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                    .addDependingDetectionRules(
                            BcBlockCipher.all(
                                    new CipherContext(
                                            Map.of("kind", "BLOCK_CIPHER_ENGINE_FOR_AEAD"))))
                    .buildForContext(new CipherContext(Map.of("kind", "AEAD_BLOCK_CIPHER")))
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(BcAEADCipherInit.rules());

    private static final IDetectionRule<Tree> CONSTRUCTOR_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.modes." + MODE)
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>(MODE))
                    .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                    .addDependingDetectionRules(
                            BcBlockCipher.all(
                                    new CipherContext(
                                            Map.of("kind", "BLOCK_CIPHER_ENGINE_FOR_AEAD"))))
                    .withMethodParameter("org.bouncycastle.crypto.modes.gcm.GCMMultiplier")
                    .buildForContext(new CipherContext(Map.of("kind", "AEAD_BLOCK_CIPHER")))
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(BcAEADCipherInit.rules());

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW_INSTANCE_1, NEW_INSTANCE_2, CONSTRUCTOR_1, CONSTRUCTOR_2);
    }
}
