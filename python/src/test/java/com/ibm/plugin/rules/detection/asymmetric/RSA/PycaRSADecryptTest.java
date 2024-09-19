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
package com.ibm.plugin.rules.detection.asymmetric.RSA;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Digest;
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

class PycaRSADecryptTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/RSA/PycaRSADecryptTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            /*
             * Detection Store
             */
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(PrivateKeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(KeySize.class);
            assertThat(value0.asString()).isEqualTo("1024");

            DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_1 =
                    getStoreOfValueType(CipherAction.class, detectionStore.getChildren());
            assertThat(store_1).isNotNull();
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(CipherAction.class);
            assertThat(value0_1.asString()).isEqualTo("DECRYPT");

            DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_1_1 =
                    getStoreOfValueType(ValueAction.class, store_1.getChildren());
            assertThat(store_1_1).isNotNull();
            assertThat(store_1_1.getDetectionValues()).hasSize(1);
            assertThat(store_1_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1_1 = store_1_1.getDetectionValues().get(0);
            assertThat(value0_1_1).isInstanceOf(ValueAction.class);
            assertThat(value0_1_1.asString()).isEqualTo("OAEP");

            List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>> stores =
                    getStoresOfValueType(ValueAction.class, store_1_1.getChildren());
            assertThat(stores).isNotNull();
            for (DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> s : stores) {
                assertThat(s.getDetectionValues()).hasSize(1);
                assertThat(s.getDetectionValueContext())
                        .isInstanceOfAny(SignatureContext.class, DigestContext.class);
                IValue<Tree> v = s.getDetectionValues().get(0);
                assertThat(v).isInstanceOf(ValueAction.class);
                assertThat(v.asString())
                        .satisfiesAnyOf(
                                str -> assertThat(str).isEqualTo("MGF1"),
                                str -> assertThat(str).isEqualTo("SHA256"));

                if (s.getDetectionValueContext().is(SignatureContext.class)) {
                    DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_1_1_1_1 =
                            getStoreOfValueType(ValueAction.class, s.getChildren());
                    assertThat(store_1_1_1_1).isNotNull();
                    assertThat(store_1_1_1_1.getDetectionValues()).hasSize(1);
                    assertThat(store_1_1_1_1.getDetectionValueContext())
                            .isInstanceOf(DigestContext.class);
                    IValue<Tree> value0_1_1_1_1 = store_1_1_1_1.getDetectionValues().get(0);
                    assertThat(value0_1_1_1_1).isInstanceOf(ValueAction.class);
                    assertThat(value0_1_1_1_1.asString()).isEqualTo("SHA384");
                }
            }

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PrivateKey
            INode privateKeyNode = nodes.get(0);
            assertThat(privateKeyNode.getKind()).isEqualTo(PrivateKey.class);
            assertThat(privateKeyNode.getChildren()).hasSize(4);
            assertThat(privateKeyNode.asString()).isEqualTo("RSA");

            // KeyGeneration under PrivateKey
            INode keyGenerationNode = privateKeyNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

            // PublicKeyEncryption under PrivateKey
            INode pke = privateKeyNode.getChildren().get(PublicKeyEncryption.class);
            assertThat(pke).isNotNull();
            assertThat(pke.getChildren()).hasSize(2);
            assertThat(pke.asString()).isEqualTo("RSA-OAEP");

            // Oid under Signature under PrivateKey
            INode oidNode = pke.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.1.1.7");

            // Padding under Signature under PrivateKey
            INode paddingNode = pke.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).hasSize(2);
            assertThat(paddingNode.asString()).isEqualTo("OAEP");

            // MessageDigest under Padding under Signature under PrivateKey
            INode messageDigestNode = paddingNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA256");

            // Oid under MessageDigest under Padding under Signature under PrivateKey
            INode oidNode1 = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

            // Digest under MessageDigest under Padding under Signature under PrivateKey
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // BlockSize under MessageDigest under Padding under Signature under PrivateKey
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // DigestSize under MessageDigest under Padding under Signature under PrivateKey
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");

            // MaskGenerationFunction under Padding under Signature under PrivateKey
            INode maskGenerationFunctionNode =
                    paddingNode.getChildren().get(MaskGenerationFunction.class);
            assertThat(maskGenerationFunctionNode).isNotNull();
            assertThat(maskGenerationFunctionNode.getChildren()).hasSize(2);
            assertThat(maskGenerationFunctionNode.asString()).isEqualTo("MGF1");

            // Oid under MaskGenerationFunction under Padding under Signature under PrivateKey
            INode oidNode2 = maskGenerationFunctionNode.getChildren().get(Oid.class);
            assertThat(oidNode2).isNotNull();
            assertThat(oidNode2.getChildren()).isEmpty();
            assertThat(oidNode2.asString()).isEqualTo("1.2.840.113549.1.1.8");

            // MessageDigest under MaskGenerationFunction under Padding under Signature under
            // PrivateKey
            INode messageDigestNode1 =
                    maskGenerationFunctionNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode1).isNotNull();
            assertThat(messageDigestNode1.getChildren()).hasSize(4);
            assertThat(messageDigestNode1.asString()).isEqualTo("SHA384");

            // Oid under MessageDigest under MaskGenerationFunction under Padding under Signature
            // under PrivateKey
            INode oidNode3 = messageDigestNode1.getChildren().get(Oid.class);
            assertThat(oidNode3).isNotNull();
            assertThat(oidNode3.getChildren()).isEmpty();
            assertThat(oidNode3.asString()).isEqualTo("2.16.840.1.101.3.4.2.2");

            // Digest under MessageDigest under MaskGenerationFunction under Padding under Signature
            // under PrivateKey
            INode digestNode1 = messageDigestNode1.getChildren().get(Digest.class);
            assertThat(digestNode1).isNotNull();
            assertThat(digestNode1.getChildren()).isEmpty();
            assertThat(digestNode1.asString()).isEqualTo("DIGEST");

            // BlockSize under MessageDigest under MaskGenerationFunction under Padding under
            // Signature under PrivateKey
            INode blockSizeNode1 = messageDigestNode1.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode1).isNotNull();
            assertThat(blockSizeNode1.getChildren()).isEmpty();
            assertThat(blockSizeNode1.asString()).isEqualTo("1024");

            // DigestSize under MessageDigest under MaskGenerationFunction under Padding under
            // Signature under PrivateKey
            INode digestSizeNode1 = messageDigestNode1.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode1).isNotNull();
            assertThat(digestSizeNode1.getChildren()).isEmpty();
            assertThat(digestSizeNode1.asString()).isEqualTo("384");

            // Decrypt under PrivateKey
            INode decryptNode = privateKeyNode.getChildren().get(Decrypt.class);
            assertThat(decryptNode).isNotNull();
            assertThat(decryptNode.getChildren()).isEmpty();
            assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

            // KeyLength under PrivateKey
            INode keyLengthNode = privateKeyNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("1024");
        }
    }
}
