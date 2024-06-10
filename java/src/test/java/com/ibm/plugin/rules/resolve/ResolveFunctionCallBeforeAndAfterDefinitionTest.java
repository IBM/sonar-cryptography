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
package com.ibm.plugin.rules.resolve;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class ResolveFunctionCallBeforeAndAfterDefinitionTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/resolve/ResolveFunctionCallBeforeAndAfterDefinitionTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            IValue<Tree> value = detectionStore.getDetectionValues().get(0);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            assertThat(value).isInstanceOf(Algorithm.class);
            assertThat(value.asString()).isEqualTo("RSA/ECB/PKCS1Padding");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> operation =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(operation).isNotNull();
            assertThat(operation.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            assertThat(operation.getDetectionValues()).hasSize(1);
            value = operation.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(OperationMode.class);
            assertThat(value.asString()).isEqualTo("1");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> aes1 =
                    getStoreOfValueType(Algorithm.class, operation.getChildren());
            assertThat(aes1).isNotNull();
            assertThat(aes1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            assertThat(aes1.getDetectionValues()).hasSize(1);
            value = aes1.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(Algorithm.class);
            assertThat(value.asString()).isEqualTo("AES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> keySize =
                    getStoreOfValueType(KeySize.class, aes1.getChildren());
            assertThat(keySize).isNotNull();
            assertThat(keySize.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            assertThat(keySize.getDetectionValues()).hasSize(1);
            value = keySize.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(KeySize.class);
            assertThat(value.asString()).isEqualTo("128");
        } else if (findingId == 1) {
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            IValue<Tree> value = detectionStore.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(Algorithm.class);
            assertThat(value.asString()).isEqualTo("AES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> keySize =
                    getStoreOfValueType(KeySize.class, detectionStore.getChildren());
            assertThat(keySize).isNotNull();
            assertThat(keySize.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            assertThat(keySize.getDetectionValues()).hasSize(1);
            value = keySize.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(KeySize.class);
            assertThat(value.asString()).isEqualTo("128");
        } else if (findingId == 2) {
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            IValue<Tree> value = detectionStore.getDetectionValues().get(0);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            assertThat(value).isInstanceOf(Algorithm.class);
            assertThat(value.asString()).isEqualTo("AES/ECB/PKCS5Padding");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> operation =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(operation).isNotNull();
            assertThat(operation.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            assertThat(operation.getDetectionValues()).hasSize(1);
            value = operation.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(OperationMode.class);
            assertThat(value.asString()).isEqualTo("2");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> aes1 =
                    getStoreOfValueType(Algorithm.class, operation.getChildren());
            assertThat(aes1).isNotNull();
            assertThat(aes1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            assertThat(aes1.getDetectionValues()).hasSize(1);
            value = aes1.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(Algorithm.class);
            assertThat(value.asString()).isEqualTo("AES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> keySize =
                    getStoreOfValueType(KeySize.class, aes1.getChildren());
            assertThat(keySize).isNotNull();
            assertThat(keySize.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            assertThat(keySize.getDetectionValues()).hasSize(1);
            value = keySize.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(KeySize.class);
            assertThat(value.asString()).isEqualTo("128");
        }
    }
}
