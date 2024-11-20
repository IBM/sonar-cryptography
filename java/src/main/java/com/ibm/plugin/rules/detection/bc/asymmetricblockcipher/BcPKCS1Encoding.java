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
package com.ibm.plugin.rules.detection.bc.asymmetricblockcipher;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BYTE_ARRAY_TYPE;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcPKCS1Encoding {

    private BcPKCS1Encoding() {
        // nothing
    }

    private static final List<IDetectionRule<Tree>> constructors(
            @Nullable IDetectionContext encodingDetectionValueContext,
            @Nullable IDetectionContext engineDetectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                encodingDetectionValueContext != null
                        ? encodingDetectionValueContext
                        : new CipherContext(Map.of("kind", "ENCODING"));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.encodings.PKCS1Encoding")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("PKCS1Encoding"))
                        .withMethodParameter("org.bouncycastle.crypto.AsymmetricBlockCipher")
                        .addDependingDetectionRules(
                                BcAsymCipherEngine.rules(engineDetectionValueContext))
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcAsymCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.encodings.PKCS1Encoding")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("PKCS1Encoding"))
                        .withMethodParameter("org.bouncycastle.crypto.AsymmetricBlockCipher")
                        .addDependingDetectionRules(
                                BcAsymCipherEngine.rules(engineDetectionValueContext))
                        .withMethodParameter(BYTE_ARRAY_TYPE)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcAsymCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.encodings.PKCS1Encoding")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("PKCS1Encoding"))
                        .withMethodParameter("org.bouncycastle.crypto.AsymmetricBlockCipher")
                        .addDependingDetectionRules(
                                BcAsymCipherEngine.rules(engineDetectionValueContext))
                        .withMethodParameter("int")
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcAsymCipherInit.rules()));

        return constructorsList;
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return rules(null, null);
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext encodingDetectionValueContext,
            @Nullable IDetectionContext engineDetectionValueContext) {
        return constructors(encodingDetectionValueContext, engineDetectionValueContext);
    }
}
