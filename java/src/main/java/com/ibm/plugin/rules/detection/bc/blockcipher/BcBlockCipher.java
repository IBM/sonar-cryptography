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
package com.ibm.plugin.rules.detection.bc.blockcipher;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.BlockSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcBlockCipher {
    private BcBlockCipher() {
        // nothing
    }

    /*
     * Classes implementing BlockCipher having a simple constructor
     * taking a BlockCipher as only argument.
     * "|" is used as a separator between the block cipher and the mode.
     */
    private static BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        infoMap.putKey("CBCBlockCipher");
        infoMap.putKey("G3413CBCBlockCipher").putName("GOST R 34.12-2015|CBC");
        infoMap.putKey("G3413CFBBlockCipher").putName("GOST R 34.12-2015|CFB");
        infoMap.putKey("G3413CTRBlockCipher").putName("GOST R 34.12-2015|CTR");
        infoMap.putKey("G3413OFBBlockCipher").putName("GOST R 34.12-2015|OFB");
        infoMap.putKey("GCFBBlockCipher").putName("GOST 28147-89|CFB");
        infoMap.putKey("GOFBBlockCipher").putName("GOST 28147-89|OFB");
        infoMap.putKey("KCTRBlockCipher").putName("DSTU 7624:2014|CTR");
        infoMap.putKey("OpenPGPCFBBlockCipher").putName("CFB");
        infoMap.putKey("SICBlockCipher");
    }

    private static final List<IDetectionRule<Tree>> simpleConstructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null
                        ? detectionValueContext
                        : new CipherContext(CipherContext.Kind.BLOCK_CIPHER);

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String blockCipher = entry.getKey();
            String blockCipherName = infoMap.getDisplayName(blockCipher, "BlockCipher");
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.modes." + blockCipher)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(blockCipherName))
                            .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                            .addDependingDetectionRules(BcBlockCipherEngine.rules())
                            .buildForContext(context)
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcBlockCipherInit.rules()));
        }
        return constructorsList;
    }

    private static final List<IDetectionRule<Tree>> specialConstructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null
                        ? detectionValueContext
                        : new CipherContext(CipherContext.Kind.BLOCK_CIPHER);

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.CBCBlockCipher")
                        .forMethods("newInstance")
                        .shouldBeDetectedAs(new ValueActionFactory<>("CBC"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.SICBlockCipher")
                        .forMethods("newInstance")
                        .shouldBeDetectedAs(new ValueActionFactory<>("SIC"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.CFBBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("CFB"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.CFBBlockCipher")
                        .forMethods("newInstance")
                        .shouldBeDetectedAs(new ValueActionFactory<>("CFB"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.G3413CFBBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(
                                new ValueActionFactory<>(
                                        infoMap.getDisplayName("G3413CFBBlockCipher")))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.G3413CTRBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(
                                new ValueActionFactory<>(
                                        infoMap.getDisplayName("G3413CTRBlockCipher")))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.OFBBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("OFB"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        // TODO: forExactObjectTypes(...)
                        .forObjectTypes("org.bouncycastle.crypto.modes.PGPCFBBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("CFB"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("boolean")
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        return constructorsList;
    }

    @Unmodifiable
    @Nonnull
    // Rules defined in this file (classes finishing with BlockCipher)
    public static List<IDetectionRule<Tree>> rules() {
        return rules(null);
    }

    @Unmodifiable
    @Nonnull
    // All BlockCipher rules including all the engines
    public static List<IDetectionRule<Tree>> all() {
        return all(null);
    }

    @Unmodifiable
    @Nonnull
    // Rules defined in this file (classes finishing with BlockCipher)
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return Stream.of(
                        simpleConstructors(detectionValueContext).stream(),
                        specialConstructors(detectionValueContext).stream())
                .flatMap(i -> i)
                .toList();
    }

    @Unmodifiable
    @Nonnull
    // All BlockCipher rules including all the engines
    public static List<IDetectionRule<Tree>> all(
            @Nullable IDetectionContext detectionValueContext) {
        return Stream.of(
                        rules(detectionValueContext).stream(),
                        BcBlockCipherEngine.rules(detectionValueContext).stream())
                .flatMap(i -> i)
                .toList();
    }
}
