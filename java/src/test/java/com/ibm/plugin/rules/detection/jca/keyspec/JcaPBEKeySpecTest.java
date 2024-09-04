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
package com.ibm.plugin.rules.detection.jca.keyspec;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.PasswordSize;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaPBEKeySpecTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/jca/keyspec/JcaPBEKeySpecTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("PBKDF2WithHmacSHA1");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store =
                getStoreOfValueType(KeySize.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
        SecretKeyContext secretKeyContext = (SecretKeyContext) store.getDetectionValueContext();
        assertThat(secretKeyContext.kind()).isEqualTo(KeyContext.Kind.PBE);

        assertThat(store.getDetectionValues()).hasSize(3);
        List<IValue<Tree>> values = store.getDetectionValues();
        assertThat(values)
                .anyMatch(
                        v -> {
                            if (v instanceof KeySize<Tree>) {
                                return v.asString().equals("1024");
                            } else if (v instanceof SaltSize<Tree>) {
                                return v.asString().equals("192");
                            } else if (v instanceof PasswordSize<Tree>) {
                                return v.asString().equals("32");
                            }
                            return false;
                        });

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // SecretKey
        INode secretKeyNode = nodes.get(0);
        assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
        assertThat(secretKeyNode.getChildren()).hasSize(4);
        assertThat(secretKeyNode.asString()).isEqualTo("PBKDF2-SHA1");

        // PasswordBasedKeyDerivationFunction under SecretKey
        INode passwordBasedKeyDerivationFunctionNode =
                secretKeyNode.getChildren().get(PasswordBasedKeyDerivationFunction.class);
        assertThat(passwordBasedKeyDerivationFunctionNode).isNotNull();
        assertThat(passwordBasedKeyDerivationFunctionNode.getChildren()).hasSize(3);
        assertThat(passwordBasedKeyDerivationFunctionNode.asString()).isEqualTo("PBKDF2-SHA1");

        // Mac under PasswordBasedKeyDerivationFunction under SecretKey
        INode macNode = passwordBasedKeyDerivationFunctionNode.getChildren().get(Mac.class);
        assertThat(macNode).isNotNull();
        assertThat(macNode.getChildren()).hasSize(1);
        assertThat(macNode.asString()).isEqualTo("SHA1");

        // Tag under Mac under PasswordBasedKeyDerivationFunction under SecretKey
        INode tagNode = macNode.getChildren().get(Tag.class);
        assertThat(tagNode).isNotNull();
        assertThat(tagNode.getChildren()).isEmpty();
        assertThat(tagNode.asString()).isEqualTo("TAG");

        // KeyGeneration under PasswordBasedKeyDerivationFunction under SecretKey
        INode keyGenerationNode =
                passwordBasedKeyDerivationFunctionNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.getChildren()).isEmpty();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // Oid under PasswordBasedKeyDerivationFunction under SecretKey
        INode oidNode = passwordBasedKeyDerivationFunctionNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.1.5.12");

        // KeyLength under SecretKey
        INode keyLengthNode = secretKeyNode.getChildren().get(KeyLength.class);
        assertThat(keyLengthNode).isNotNull();
        assertThat(keyLengthNode.getChildren()).isEmpty();
        assertThat(keyLengthNode.asString()).isEqualTo("1024");

        // PasswordLength under SecretKey
        INode passwordLengthNode = secretKeyNode.getChildren().get(PasswordLength.class);
        assertThat(passwordLengthNode).isNotNull();
        assertThat(passwordLengthNode.getChildren()).isEmpty();
        assertThat(passwordLengthNode.asString()).isEqualTo("32");

        // SaltLength under SecretKey
        INode saltLengthNode = secretKeyNode.getChildren().get(SaltLength.class);
        assertThat(saltLengthNode).isNotNull();
        assertThat(saltLengthNode.getChildren()).isEmpty();
        assertThat(saltLengthNode.asString()).isEqualTo("192");
    }
}
