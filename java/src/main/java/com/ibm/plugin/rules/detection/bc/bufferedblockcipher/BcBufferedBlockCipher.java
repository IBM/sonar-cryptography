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
package com.ibm.plugin.rules.detection.bc.bufferedblockcipher;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import com.ibm.plugin.rules.detection.bc.blockcipher.BcBlockCipher;
import com.ibm.plugin.rules.detection.bc.blockcipherpadding.BcBlockCipherPadding;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcBufferedBlockCipher {

    private BcBufferedBlockCipher() {
        // nothing
    }

    private static BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        String typePrefix = "org.bouncycastle.crypto.";
        infoMap.putKey("BufferedBlockCipher").putType(typePrefix); // <–– parent class
        infoMap.putKey("DefaultBufferedBlockCipher").putType(typePrefix); // <–– parent class
        infoMap.putKey("CTSBlockCipher").putType(typePrefix + "modes.");
        infoMap.putKey("KXTSBlockCipher")
                .putName("DSTU 7624:2014|XTS")
                .putType(typePrefix + "modes.");
        infoMap.putKey("OldCTSBlockCipher").putName("CTS").putType(typePrefix + "modes.");
        infoMap.putKey("PaddedBlockCipher").putType(typePrefix + "modes.");
        infoMap.putKey("PaddedBufferedBlockCipher")
                .putName("PaddedBuffered(PKCS7)") /* the simple constructor uses PKCS7 padding */
                .putType(typePrefix + "paddings.");
    }

    private static @NotNull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String blockCipher = entry.getKey();
            String blockCipherName = infoMap.getDisplayName(blockCipher, "BlockCipher");
            String type = entry.getValue().getType();
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectExactTypes(type + blockCipher)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(blockCipherName))
                            .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                            .addDependingDetectionRules(BcBlockCipher.all())
                            .buildForContext(
                                    new CipherContext(CipherContext.Kind.BUFFERED_BLOCK_CIPHER))
                            .inBundle(() -> "BcBufferedBlockCipher")
                            .withDependingDetectionRules(BcBufferedBlockCipherInit.rules()));
        }
        return constructorsList;
    }

    private static @NotNull List<IDetectionRule<Tree>> specialConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes("org.bouncycastle.crypto.modes.NISTCTSBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("CTS"))
                        .withMethodParameter("int")
                        // TODO: "Type": should it be detected?
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipher.all())
                        .buildForContext(
                                new CipherContext(CipherContext.Kind.BUFFERED_BLOCK_CIPHER))
                        .inBundle(() -> "BcBufferedBlockCipher")
                        .withDependingDetectionRules(BcBufferedBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes( // TODO: change for forObjectExactTypes
                                "org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("PaddedBuffered"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipher.all())
                        .withMethodParameter("org.bouncycastle.crypto.paddings.BlockCipherPadding")
                        .addDependingDetectionRules(BcBlockCipherPadding.rules())
                        .buildForContext(
                                new CipherContext(CipherContext.Kind.BUFFERED_BLOCK_CIPHER))
                        .inBundle(() -> "BcBufferedBlockCipher")
                        .withDependingDetectionRules(BcBufferedBlockCipherInit.rules()));

        return constructorsList;
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return Stream.of(simpleConstructors().stream(), specialConstructors().stream())
                .flatMap(i -> i)
                .toList();
    }
}
