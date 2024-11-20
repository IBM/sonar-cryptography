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
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcStreamCipherEngine {

    private BcStreamCipherEngine() {
        // private
    }

    /*
     * Engine classes implementing StreamCipher having a simple constructor taking no argument.
     * Note that ChaChaEngine, Salsa20Engine and Zuc256Engine additionaly have a constructor
     * taking an int as parameter.
     */
    private static final List<String> engines =
            Arrays.asList(
                    "ChaCha7539Engine",
                    "ChaChaEngine",
                    "Grain128Engine",
                    "Grainv1Engine",
                    "HC128Engine",
                    "HC256Engine",
                    "ISAACEngine",
                    "RC4Engine",
                    "Salsa20Engine",
                    "VMPCEngine",
                    "VMPCKSA3Engine",
                    "XSalsa20Engine",
                    "Zuc128Engine",
                    "Zuc256Engine");

    private static @Nonnull List<IDetectionRule<Tree>> constructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (String engine : engines) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectExactTypes("org.bouncycastle.crypto.engines." + engine)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(engine))
                            // We want to capture all possible constructors (some have arguments)
                            .withAnyParameters()
                            .buildForContext(
                                    new CipherContext(Map.of("kind", "STREAM_CIPHER_ENGINE")))
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcStreamCipherInit.rules()));
        }
        return constructorsList;
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return constructors();
    }
}
