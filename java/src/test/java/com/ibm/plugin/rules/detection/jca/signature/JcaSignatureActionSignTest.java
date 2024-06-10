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
package com.ibm.plugin.rules.detection.jca.signature;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.*;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaSignatureActionSignTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/signature/JcaSignatureActionSignTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    /**
     * DEBUG [detectionStore] (SignatureContext, Algorithm) SHA384withDSA DEBUG [detectionStore] └─
     * (SignatureContext, SignatureAction) Sign DEBUG [translation] (Signature) SHA384withDSA DEBUG
     * [translation] └─ (Algorithm) DSA DEBUG [translation] └─ (Functionality) SIGN DEBUG
     * [translation] └─ (MessageDigest) SHA-384 DEBUG [translation] └─ (DigestSize) 384 DEBUG
     * [translation] └─ (BlockSize) 1024 DEBUG [translation] └─ (KeyLength) 384
     */
    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("SHA384withDSA");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store =
                getStoreOfValueType(SignatureAction.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(SignatureAction.class);
        assertThat(value.asString()).isEqualTo("SIGN");
        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(Signature.class);
        assertThat(node.asString()).isEqualTo("SHA384withDSA");

        INode algorithm = node.getChildren().get(com.ibm.mapper.model.Algorithm.class);
        assertThat(algorithm).isNotNull();
        assertThat(algorithm.asString()).isEqualTo("DSA");

        INode sign = node.getChildren().get(Sign.class);
        assertThat(sign).isNotNull();
        assertThat(sign.asString()).isEqualTo("SIGN");

        INode digest = node.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull();
        assertThat(digest.asString()).isEqualTo("SHA-384");

        INode keyLength = digest.getChildren().get(KeyLength.class);
        assertThat(keyLength).isNotNull();
        assertThat(keyLength.asString()).isEqualTo("384");

        INode digestSize = digest.getChildren().get(DigestSize.class);
        assertThat(digestSize).isNotNull();
        assertThat(digestSize.asString()).isEqualTo("384");

        INode blockSize = digest.getChildren().get(BlockSize.class);
        assertThat(blockSize).isNotNull();
        assertThat(blockSize.asString()).isEqualTo("1024");
    }
}
