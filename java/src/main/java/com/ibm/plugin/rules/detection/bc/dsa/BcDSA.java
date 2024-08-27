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
package com.ibm.plugin.rules.detection.bc.dsa;

import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcDSA {

    private BcDSA() {
        // nothing
    }

    /* TODO: maybe the function `extractSecret` would be a better entry point than the constructors? */

    // static {
    //     infoMap.putKey("DSASigner");
    //     infoMap.putKey("DSTU4145Signer").putName("DSTU 4145-2002");
    //     infoMap.putKey("ECDSASigner");
    //     infoMap.putKey("ECGOST3410_2012Signer").putName("GOST R 34.10-2012");
    //     infoMap.putKey("ECGOST3410Signer").putName("GOST R 34.10-2001");
    //     infoMap.putKey("ECNRSigner").putName("EC-NR");
    //     infoMap.putKey("GOST3410Signer").putName("GOST R 34.10-94");
    // }

    public static final List<String> dsas =
            List.of(
                    "DSASigner",
                    "DSTU4145Signer",
                    "ECDSASigner",
                    "ECGOST3410_2012Signer",
                    "ECGOST3410Signer",
                    "ECNRSigner",
                    "GOST3410Signer");

    private static @NotNull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (String dsa : dsas) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.signers." + dsa)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(dsa))
                            // We want to capture all possible constructors (some have arguments)
                            .withAnyParameters()
                            .buildForContext(new SignatureContext(SignatureContext.Kind.DSA))
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcDSAInit.rules()));
        }
        return constructorsList;
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return simpleConstructors();
    }
}
