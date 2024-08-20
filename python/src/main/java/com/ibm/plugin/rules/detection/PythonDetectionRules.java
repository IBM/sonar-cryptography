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
package com.ibm.plugin.rules.detection;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.aead.CryptographyAEAD;
import com.ibm.plugin.rules.detection.aead.CryptographyAES;
import com.ibm.plugin.rules.detection.asymmetric.CryptographyDSA;
import com.ibm.plugin.rules.detection.asymmetric.CryptographyDiffieHellman;
import com.ibm.plugin.rules.detection.asymmetric.CryptographyEllipticCurve;
import com.ibm.plugin.rules.detection.asymmetric.CryptographyGenerate;
import com.ibm.plugin.rules.detection.asymmetric.CryptographyRSA;
import com.ibm.plugin.rules.detection.asymmetric.CryptographySign;
import com.ibm.plugin.rules.detection.fernet.CryptographyFernet;
import com.ibm.plugin.rules.detection.kdf.CryptographyKDF;
import com.ibm.plugin.rules.detection.mac.CryptographyMAC;
import com.ibm.plugin.rules.detection.symmetric.CryptographyCipher;
import com.ibm.plugin.rules.detection.wrapping.CryptographyWrapping;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PythonDetectionRules {
    private PythonDetectionRules() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return Stream.of(
                        // rules
                        CryptographyGenerate.rules().stream(),
                        CryptographySign.rules().stream(),
                        CryptographyEllipticCurve.rules().stream(),
                        CryptographyRSA.rules().stream(),
                        CryptographyDiffieHellman.rules().stream(),
                        CryptographyDSA.rules().stream(),
                        CryptographyAEAD.rules().stream(),
                        CryptographyAES.rules().stream(),
                        CryptographyCipher.rules().stream(),
                        CryptographyMAC.rules().stream(),
                        CryptographyWrapping.rules().stream(),
                        CryptographyKDF.rules().stream(),
                        CryptographyFernet.rules().stream())
                .flatMap(i -> i)
                .toList();
    }
}
