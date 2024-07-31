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

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcBlockCipherEngine {

    private BcBlockCipherEngine() {
        // nothing
    }

    private static BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        infoMap.putKey("AESEngine").putName("AES");
        infoMap.putKey("AESFastEngine").putName("AES");
        infoMap.putKey("AESLightEngine").putName("AES");
        infoMap.putKey("ARIAEngine").putName("ARIA");
        infoMap.putKey("BlowfishEngine").putName("Blowfish");
        infoMap.putKey("CamelliaEngine").putName("Camellia");
        infoMap.putKey("CamelliaLightEngine").putName("Camellia");
        infoMap.putKey("CAST5Engine").putName("CAST5");
        infoMap.putKey("CAST6Engine").putName("CAST5");
        infoMap.putKey("DESedeEngine").putName("DESede");
        infoMap.putKey("DESEngine").putName("DES");
        infoMap.putKey("DSTU7624Engine").putName("DSTU 7624:2014");
        infoMap.putKey("GOST28147Engine").putName("GOST 28147-89");
        infoMap.putKey("GOST3412_2015Engine").putName("GOST R 34.12-2015");
        infoMap.putKey("IDEAEngine").putName("IDEA");
        infoMap.putKey("LEAEngine").putName("LEA");
        infoMap.putKey("NoekeonEngine").putName("Noekeon");
        infoMap.putKey("NullEngine").putName("Null");
        infoMap.putKey("RC2Engine").putName("RC2");
        infoMap.putKey("RC532Engine").putName("RC532");
        infoMap.putKey("RC564Engine").putName("RC564");
        infoMap.putKey("RC6Engine").putName("RC6");
        infoMap.putKey("RijndaelEngine").putName("Rijndael");
        infoMap.putKey("SEEDEngine").putName("SEED");
        infoMap.putKey("SerpentEngine").putName("Serpent");
        infoMap.putKey("Shacal2Engine").putName("Shacal2");
        infoMap.putKey("SkipjackEngine").putName("Skipjack");
        infoMap.putKey("SM4Engine").putName("SM4");
        infoMap.putKey("TEAEngine").putName("TEA");
        infoMap.putKey("ThreefishEngine").putName("Threefish");
        infoMap.putKey("TnepresEngine").putName("Tnepres");
        infoMap.putKey("TwofishEngine").putName("Twofish");
        infoMap.putKey("XTEAEngine").putName("XTEA");
    }

    private static final List<IDetectionRule<Tree>> constructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null
                        ? detectionValueContext
                        : new CipherContext(CipherContext.Kind.BLOCK_CIPHER_ENGINE);

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String engine = entry.getKey();
            String engineName = infoMap.getDisplayName(engine);
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.engines." + engine)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(engineName))
                            // We want to capture all possible constructors (some have arguments)
                            .withAnyParameters()
                            .buildForContext(context)
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcBlockCipherInit.rules()));

            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.engines." + engine)
                            .forMethods("newInstance")
                            .shouldBeDetectedAs(new ValueActionFactory<>(engineName))
                            // We want to capture all possible constructors (some have arguments)
                            .withAnyParameters()
                            .buildForContext(context)
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcBlockCipherInit.rules()));
        }

        return constructorsList;
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return rules(null);
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return constructors(detectionValueContext);
    }
}
