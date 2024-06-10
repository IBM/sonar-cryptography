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
package com.ibm.plugin.rules.detection.bc.signer;

import com.ibm.engine.model.context.SignatureContext;
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

public final class BcSimpleSigner {

    private BcSimpleSigner() {
        // nothing
    }

    /* TODO: maybe the function `extractSecret` would be a better entry point than the constructors? */

    private static BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        infoMap.putKey("Ed25519Signer").putName("Ed25519"); // standard algorithm
        infoMap.putKey("Ed25519phSigner").putName("Ed25519"); // prehashed variant
        infoMap.putKey("Ed25519ctxSigner").putName("Ed25519"); // contextual variant

        infoMap.putKey("Ed448Signer").putName("Ed448"); // standard algorithm
        infoMap.putKey("Ed448phSigner").putName("Ed448"); // prehashed variant
    }

    private static @NotNull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String signer = entry.getKey();
            String signerName = infoMap.getDisplayName(signer);
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.signers." + signer)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(signerName))
                            // We want to capture all possible constructors (some have arguments)
                            .withAnyParameters()
                            .buildForContext(new SignatureContext(SignatureContext.Kind.EdDSA))
                            .inBundle(() -> "bcSimpleSigner")
                            .withDependingDetectionRules(BcSignerInit.rules()));
        }
        return constructorsList;
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return simpleConstructors();
    }
}
