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
package com.ibm.plugin.rules.detection.bc.blockcipherpadding;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcBlockCipherPadding {
    private BcBlockCipherPadding() {
        // nothing
    }

    private static BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        infoMap.putKey("ISO10126d2Padding").putName("ISO 10126-2:1991");
        infoMap.putKey("ISO7816d4Padding").putName("ISO 7816-4:2020");
        infoMap.putKey("PKCS7Padding");
        infoMap.putKey("TBCPadding");
        infoMap.putKey("X923Padding").putName("X.923");
        infoMap.putKey("ZeroBytePadding").putName("Zero byte");
    }

    private static @NotNull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String padding = entry.getKey();
            String paddingName = infoMap.getDisplayName(padding, "Padding");
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.paddings." + padding)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(paddingName))
                            .withoutParameters()
                            .buildForContext(new CipherContext(CipherContext.Kind.PADDING))
                            .inBundle(() -> "BcBlockCipherPadding")
                            .withoutDependingDetectionRules());
        }
        return constructorsList;
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return simpleConstructors();
    }
}
