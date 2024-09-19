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
package com.ibm.plugin.rules.detection.kdf;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class PycaPBKDF2Test extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/kdf/PycaPBKDF2TestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOf(KeyDerivationFunctionContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(Algorithm.class);
        assertThat(value0.asString()).isEqualTo("SHA256");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_1 =
                getStoreOfValueType(KeySize.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext())
                .isInstanceOf(KeyDerivationFunctionContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(KeySize.class);
        assertThat(value0_1.asString()).isEqualTo("256");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_2 =
                getStoreOfValueType(AlgorithmParameter.class, detectionStore.getChildren());
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext())
                .isInstanceOf(KeyDerivationFunctionContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(AlgorithmParameter.class);
        assertThat(value0_2.asString()).isEqualTo("480000");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // PasswordBasedKeyDerivationFunction
        INode passwordBasedKeyDerivationFunctionNode = nodes.get(0);
        assertThat(passwordBasedKeyDerivationFunctionNode.getKind())
                .isEqualTo(PasswordBasedKeyDerivationFunction.class);
        assertThat(passwordBasedKeyDerivationFunctionNode.getChildren()).hasSize(3);
        assertThat(passwordBasedKeyDerivationFunctionNode.asString()).isEqualTo("PBKDF2-SHA256");

        // KeyDerivation under PasswordBasedKeyDerivationFunction
        INode keyDerivationNode =
                passwordBasedKeyDerivationFunctionNode.getChildren().get(KeyDerivation.class);
        assertThat(keyDerivationNode).isNotNull();
        assertThat(keyDerivationNode.getChildren()).isEmpty();
        assertThat(keyDerivationNode.asString()).isEqualTo("KEYDERIVATION");

        // MessageDigest under PasswordBasedKeyDerivationFunction
        INode messageDigestNode =
                passwordBasedKeyDerivationFunctionNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.getChildren()).hasSize(4);
        assertThat(messageDigestNode.asString()).isEqualTo("SHA256");

        // Digest under MessageDigest under PasswordBasedKeyDerivationFunction
        INode digestNode = messageDigestNode.getChildren().get(Digest.class);
        assertThat(digestNode).isNotNull();
        assertThat(digestNode.getChildren()).isEmpty();
        assertThat(digestNode.asString()).isEqualTo("DIGEST");

        // BlockSize under MessageDigest under PasswordBasedKeyDerivationFunction
        INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.getChildren()).isEmpty();
        assertThat(blockSizeNode.asString()).isEqualTo("512");

        // DigestSize under MessageDigest under PasswordBasedKeyDerivationFunction
        INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
        assertThat(digestSizeNode).isNotNull();
        assertThat(digestSizeNode.getChildren()).isEmpty();
        assertThat(digestSizeNode.asString()).isEqualTo("256");

        // Oid under MessageDigest under PasswordBasedKeyDerivationFunction
        INode oidNode = messageDigestNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

        // KeyLength under PasswordBasedKeyDerivationFunction
        INode keyLengthNode =
                passwordBasedKeyDerivationFunctionNode.getChildren().get(KeyLength.class);
        assertThat(keyLengthNode).isNotNull();
        assertThat(keyLengthNode.getChildren()).isEmpty();
        assertThat(keyLengthNode.asString()).isEqualTo("256");
    }
}
