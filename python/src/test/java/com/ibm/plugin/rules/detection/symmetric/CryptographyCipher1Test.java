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
package com.ibm.plugin.rules.detection.symmetric;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class CryptographyCipher1Test extends TestBase {
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/symmetric/CryptographyCipher1TestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(2);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);

        // First entry
        IValue<Tree> value1 = detectionStore.getDetectionValues().get(0);
        assertThat(value1).isInstanceOf(Algorithm.class);
        assertThat(value1.asString()).isEqualTo("AES");

        // Second entry
        IValue<Tree> value2 = detectionStore.getDetectionValues().get(1);
        assertThat(value2).isInstanceOf(Algorithm.class);
        assertThat(value2.asString()).isEqualTo("CBC");

        // Children
        List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>> children =
                detectionStore.getChildren();

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> child = children.get(0);
        assertThat(child.getDetectionValues()).hasSize(1);
        assertThat(child.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value3 = child.getDetectionValues().get(0);
        assertThat(value3).isInstanceOf(CipherAction.class);
        assertThat(value3.asString()).isEqualTo("DECRYPT");

        child = children.get(1);
        assertThat(child.getDetectionValues()).hasSize(1);
        assertThat(child.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value4 = child.getDetectionValues().get(0);
        assertThat(value4).isInstanceOf(CipherAction.class);
        assertThat(value4.asString()).isEqualTo("ENCRYPT");

        child = getStoreOfValueType(Algorithm.class, children);
        assertThat(child).isNotNull();
        assertThat(child.getDetectionValues()).hasSize(1);
        assertThat(child.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> keySizeValue = child.getDetectionValues().get(0);
        assertThat(keySizeValue.asString()).isEqualTo("AES");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        INode blockCipherNode = nodes.get(0);
        assertThat(blockCipherNode).isInstanceOf(BlockCipher.class);
        assertThat(blockCipherNode.asString()).isEqualTo("AES");
        // assertThat(blockCipherNode.getChildren()).hasSize(6);

        // Mode
        INode modeNode = blockCipherNode.getChildren().get(Mode.class);
        assertThat(modeNode).isNotNull();
        assertThat(modeNode.asString()).isEqualTo("CBC");

        // Decrypt
        INode decryptNode = blockCipherNode.getChildren().get(Decrypt.class);
        assertThat(decryptNode).isNotNull();
        assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

        // BlockSize
        INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.asString()).isEqualTo("128");

        // Padding
        INode paddingNode = blockCipherNode.getChildren().get(Padding.class);
        assertThat(paddingNode).isNotNull();
        assertThat(paddingNode.asString()).isEqualTo("PKCS7");

        // Encrypt
        INode encryptNode = blockCipherNode.getChildren().get(Encrypt.class);
        assertThat(encryptNode).isNotNull();
        assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");
    }
}
