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
package com.ibm.plugin.rules.detection.bc.streamcipher;

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

public final class BcStreamCipherEngine {

    private BcStreamCipherEngine() {
        // private
    }

    private static BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        /*
         * Engine classes implementing StreamCipher having a simple
         * constructor taking no argument
         */
        infoMap.putKey("ChaCha7539Engine").putName("ChaCha");
        infoMap.putKey("ChaChaEngine");
        infoMap.putKey("Grain128Engine").putName("Grain-128"); // key size of 128 bits
        infoMap.putKey("Grainv1Engine").putName("Grain v1");
        infoMap.putKey("HC128Engine").putName("HC-128"); // key size of 128 bits
        infoMap.putKey("HC256Engine").putName("HC-256"); // key size of 256 bits
        infoMap.putKey("ISAACEngine");
        infoMap.putKey("RC4Engine");
        infoMap.putKey("Salsa20Engine");
        infoMap.putKey("VMPCEngine");
        infoMap.putKey("VMPCKSA3Engine").putName("VMPC KSA3");
        infoMap.putKey("XSalsa20Engine");
        infoMap.putKey("Zuc128Engine").putName("ZUC-128");
        infoMap.putKey("Zuc256Engine").putName("ZUC-256");
    }

    private static @NotNull List<IDetectionRule<Tree>> constructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String engine = entry.getKey();
            String engineName = infoMap.getDisplayName(engine, "Engine");

            /*
             * Note that ChaChaEngine, Salsa20Engine and Zuc256Engine additionaly have
             * a constructor taking an int as parameter.
             */
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectExactTypes("org.bouncycastle.crypto.engines." + engine)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(engineName))
                            // We want to capture all possible constructors (some have arguments)
                            .withAnyParameters()
                            .buildForContext(
                                    new CipherContext(CipherContext.Kind.STREAM_CIPHER_ENGINE))
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcStreamCipherInit.rules()));
        }
        return constructorsList;
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return constructors();
    }
}
