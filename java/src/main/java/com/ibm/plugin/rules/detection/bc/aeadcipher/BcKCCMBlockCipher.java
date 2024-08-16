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
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcKCCMBlockCipher {

    private BcKCCMBlockCipher() {
        // nothing
    }

    private static final String MODE = "KCCMBlockCipher";

    private static final IDetectionRule<Tree> CONSTRUCTOR_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.modes." + MODE)
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>(MODE))
                    .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                    .addDependingDetectionRules(BcBlockCipher.all())
                    .buildForContext(new CipherContext(CipherContext.Kind.AEAD_BLOCK_CIPHER))
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(BcAEADCipherInit.rules());

    private static final IDetectionRule<Tree> CONSTRUCTOR_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.modes." + MODE)
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>(MODE))
                    .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                    .addDependingDetectionRules(BcBlockCipher.all())
                    .withMethodParameter("int")
                    .buildForContext(new CipherContext(CipherContext.Kind.AEAD_BLOCK_CIPHER))
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(BcAEADCipherInit.rules());

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(CONSTRUCTOR_1, CONSTRUCTOR_2);
    }
}
