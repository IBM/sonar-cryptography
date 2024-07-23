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

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.configuration.TestConfig;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaCipherMapperTest {

    @Test
    void base() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaCipherMapper jcaCipherMapper = new JcaCipherMapper();
        Optional<Algorithm> cipherOptional =
                jcaCipherMapper.parse(
                        "AES/ECB/PKCS5Padding", testDetectionLocation, Configuration.DEFAULT);

        assertThat(cipherOptional).isPresent();
        assertThat(cipherOptional.get().is(BlockCipher.class)).isTrue();
        Cipher cipher = (Cipher) cipherOptional.get();

        assertThat(cipher.getName()).isEqualTo("AES");
        assertThat(cipher.getDefaultKeyLength()).isPresent();
        assertThat(cipher.getDefaultKeyLength().get().asString()).isEqualTo("128");

        assertThat(cipher.getMode()).isPresent();
        Mode mode = cipher.getMode().get();
        assertThat(mode.getName()).isEqualTo("ECB");
        assertThat(mode.getBlockSize()).isEmpty();

        assertThat(cipher.getPadding()).isPresent();
        assertThat(cipher.getPadding().get().getName()).isEqualTo("PKCS5");
    }

    @Test
    void pbe() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaCipherMapper jcaCipherMapper = new JcaCipherMapper();
        Optional<Algorithm> cipherOptional =
                jcaCipherMapper.parse(
                        "PBEWithMD5AndDES", testDetectionLocation, Configuration.DEFAULT);

        assertThat(cipherOptional).isPresent();
        assertThat(cipherOptional.get().is(PasswordBasedEncryption.class)).isTrue();
        PasswordBasedEncryption pbe = (PasswordBasedEncryption) cipherOptional.get();

        assertThat(pbe.getName()).isEqualTo("PBEWithMD5AndDES");
        assertThat(pbe.hasChildren()).isTrue();
        assertThat(pbe.getChildren().values()).hasSize(2);

        assertThat(pbe.getDigest()).isPresent();
        assertThat(pbe.getPseudoRandomFunction()).isEmpty();
        assertThat(pbe.getEncryptionAlgorithm()).isPresent();

        MessageDigest digest = pbe.getDigest().get();
        assertThat(digest.getName()).isEqualTo("MD5");
        assertThat(digest.getDigestSize()).isPresent();
        assertThat(digest.getDigestSize().get().getValue()).isEqualTo(128);
        assertThat(digest.getBlockSize()).isPresent();
        assertThat(digest.getBlockSize().get().getValue()).isEqualTo(512);

        Algorithm encryptionAlgorithm = pbe.getEncryptionAlgorithm().get();
        assertThat(encryptionAlgorithm.getName()).isEqualTo("DES");
    }

    @Test
    void blockSize() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaCipherMapper jcaCipherMapper = new JcaCipherMapper();
        Optional<Algorithm> cipherOptional =
                jcaCipherMapper.parse(
                        "AES/CFB8/NoPadding", testDetectionLocation, Configuration.DEFAULT);

        assertThat(cipherOptional).isPresent();
        assertThat(cipherOptional.get().is(BlockCipher.class)).isTrue();
        Cipher cipher = (Cipher) cipherOptional.get();

        assertThat(cipher.getName()).isEqualTo("AES");

        assertThat(cipher.getMode()).isPresent();
        Mode mode = cipher.getMode().get();
        assertThat(mode.getName()).isEqualTo("CFB");
        assertThat(mode.getBlockSize()).isPresent();
        assertThat(mode.getBlockSize().get().getValue()).isEqualTo(8);

        assertThat(cipher.getPadding()).isPresent();
        assertThat(cipher.getPadding().get().getName()).isEmpty();
    }

    @Test
    void ae() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaCipherMapper jcaCipherMapper = new JcaCipherMapper();
        Optional<Algorithm> cipherOptional =
                jcaCipherMapper.parse(
                        "AES/GCM/NoPadding", testDetectionLocation, Configuration.DEFAULT);

        assertThat(cipherOptional).isPresent();
        assertThat(cipherOptional.get().is(AuthenticatedEncryption.class)).isTrue();
    }

    @Test
    void rsa() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaCipherMapper jcaAlgorithmMapper = new JcaCipherMapper();
        Optional<? extends INode> algorithm =
                jcaAlgorithmMapper.parse("RSA", testDetectionLocation, Configuration.DEFAULT);

        assertThat(algorithm).isEmpty();
    }

    @Test
    void configuration() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaCipherMapper jcaCipherMapper = new JcaCipherMapper();
        Optional<Algorithm> cipherOptional =
                jcaCipherMapper.parse(
                        "AES/CFB8/NoPadding", testDetectionLocation, new TestConfig());

        assertThat(cipherOptional).isPresent();
        assertThat(cipherOptional.get().is(BlockCipher.class)).isTrue();
        Cipher cipher = (Cipher) cipherOptional.get();

        assertThat(cipher.getName()).isEqualTo("aes");

        assertThat(cipher.getMode()).isPresent();
        Mode mode = cipher.getMode().get();
        assertThat(mode.getName()).isEqualTo("cfb");
        assertThat(mode.getBlockSize()).isPresent();
        assertThat(mode.getBlockSize().get().getValue()).isEqualTo(8);

        assertThat(cipher.getPadding()).isPresent();
        assertThat(cipher.getPadding().get().getName()).isEmpty();
    }
}
