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
package com.ibm.mapper.mapper.jca;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaAlgorithmMapperTest {

    @Test
    void blockCipher() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> assetOptional =
                jcaAlgorithmMapper.parse("AES/CFB8/NoPadding", testDetectionLocation);
        assertThat(assetOptional).isPresent();
        assertThat(assetOptional.get().is(BlockCipher.class)).isTrue();
    }

    @Test
    void streamCipher() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> assetOptional =
                jcaAlgorithmMapper.parse("ChaCha20/NONE/NoPadding", testDetectionLocation);
        assertThat(assetOptional).isPresent();
        assertThat(assetOptional.get().is(StreamCipher.class)).isTrue();
    }

    @Test
    void aeCipher() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> assetOptional =
                jcaAlgorithmMapper.parse("AES/GCM/NoPadding", testDetectionLocation);
        assertThat(assetOptional).isPresent();
        assertThat(assetOptional.get().is(BlockCipher.class)).isTrue();
    }

    @Test
    void keyAgreement() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> assetOptional =
                jcaAlgorithmMapper.parse("X448", testDetectionLocation);
        assertThat(assetOptional).isPresent();
        assertThat(assetOptional.get().is(KeyAgreement.class)).isTrue();
    }

    @Test
    void mac() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> assetOptional =
                jcaAlgorithmMapper.parse("HmacSHA512/224", testDetectionLocation);
        assertThat(assetOptional).isPresent();
        assertThat(assetOptional.get().is(Mac.class)).isTrue();
    }

    @Test
    void digest() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> assetOptional =
                jcaAlgorithmMapper.parse("SHA-512/224", testDetectionLocation);
        assertThat(assetOptional).isPresent();
        assertThat(assetOptional.get().is(MessageDigest.class)).isTrue();
    }

    @Test
    void pbe() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> assetOptional =
                jcaAlgorithmMapper.parse("PBEWithHmacSHA256AndAES", testDetectionLocation);
        assertThat(assetOptional).isPresent();
        assertThat(assetOptional.get().is(PasswordBasedEncryption.class)).isTrue();
    }

    @Test
    void pbkdf() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> assetOptional =
                jcaAlgorithmMapper.parse("PBKDF2WithHmacSHA256", testDetectionLocation);
        assertThat(assetOptional).isPresent();
        assertThat(assetOptional.get().is(PasswordBasedKeyDerivationFunction.class)).isTrue();
    }

    @Test
    void prng() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> assetOptional =
                jcaAlgorithmMapper.parse("SHA1PRNG", testDetectionLocation);
        assertThat(assetOptional).isPresent();
        assertThat(assetOptional.get().is(PseudorandomNumberGenerator.class)).isTrue();
    }

    @Test
    void signature() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> assetOptional =
                jcaAlgorithmMapper.parse("SHA384withDSA", testDetectionLocation);
        assertThat(assetOptional).isPresent();
        assertThat(assetOptional.get().is(Signature.class)).isTrue();
    }
}
