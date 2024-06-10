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
package com.ibm.plugin.rules.detection.wrapping;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class CryptographyWrappingTest extends TestBase {
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/wrapping/CryptographyWrappingTestFile.py", this);
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);

        // First entry
        IValue<Tree> value1 = detectionStore.getDetectionValues().get(0);
        assertThat(value1).isInstanceOf(CipherAction.class);
        assertThat(value1.asString()).isEqualTo("WRAP");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        INode encapsulateNode = nodes.get(0);
        assertThat(encapsulateNode).isInstanceOf(Encapsulate.class);
        assertThat(encapsulateNode.asString()).isEqualTo("ENCAPSULATE");

        // Secret key
        INode secretKeyNode = encapsulateNode.getChildren().get(SecretKey.class);
        assertThat(secretKeyNode).isNotNull();
        assertThat(secretKeyNode.asString()).isEqualTo("AES");

        // BlockCipher
        INode blockCipherNode = secretKeyNode.getChildren().get(BlockCipher.class);
        assertThat(blockCipherNode).isNotNull();
        assertThat(blockCipherNode.asString()).isEqualTo("AES");

        // KeyGeneration
        INode keyGenNode = blockCipherNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenNode).isNotNull();
        assertThat(keyGenNode.asString()).isEqualTo("KEYGENERATION");
    }
}
