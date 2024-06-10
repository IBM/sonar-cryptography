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
import com.ibm.mapper.model.*;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaMacMapperTest {

    @Test
    void truncatedDigest() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaMacMapper jcaMacMapper = new JcaMacMapper();
        Optional<Algorithm> macOptional =
                jcaMacMapper.parse("HmacSHA512/224", testDetectionLocation, Configuration.DEFAULT);

        assertThat(macOptional).isPresent();
        assertThat(macOptional.get().getName()).isEqualTo("HmacSHA512/224");
        assertThat(macOptional.get().hasChildren()).isTrue();

        Map<Class<? extends INode>, INode> children = macOptional.get().getChildren();
        assertThat(children).hasSize(1);
        INode child = children.get(MessageDigest.class);

        assertThat(child.is(MessageDigest.class)).isTrue();
        MessageDigest messageDigest = (MessageDigest) child;
        assertThat(messageDigest.getName()).isEqualTo("SHA-512/224");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(224);
        assertThat(messageDigest.getBlockSize()).isPresent();
        assertThat(messageDigest.getBlockSize().get().getValue()).isEqualTo(1024);
        assertThat(messageDigest.hasChildren()).isTrue();

        children = messageDigest.getChildren();
        assertThat(children).hasSize(3);
    }

    @Test
    void md5() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaMacMapper jcaMacMapper = new JcaMacMapper();
        Optional<Algorithm> macOptional =
                jcaMacMapper.parse("HmacMD5", testDetectionLocation, Configuration.DEFAULT);

        assertThat(macOptional).isPresent();
        assertThat(macOptional.get().getName()).isEqualTo("HmacMD5");
        assertThat(macOptional.get().hasChildren()).isTrue();

        Map<Class<? extends INode>, INode> children = macOptional.get().getChildren();
        assertThat(children).hasSize(2);
        INode algorithm = children.get(MessageDigest.class);

        assertThat(algorithm.is(MessageDigest.class)).isTrue();
        MessageDigest messageDigest = (MessageDigest) algorithm;
        assertThat(messageDigest.getName()).isEqualTo("MD5");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(128);
        assertThat(messageDigest.getBlockSize()).isPresent();
        assertThat(messageDigest.getBlockSize().get().getValue()).isEqualTo(512);
    }

    @Test
    void pbe() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaMacMapper jcaMacMapper = new JcaMacMapper();
        Optional<Algorithm> macOptional =
                jcaMacMapper.parse(
                        "PBEWithHmacSHA256", testDetectionLocation, Configuration.DEFAULT);

        assertThat(macOptional).isPresent();
        assertThat(macOptional.get().is(PasswordBasedEncryption.class)).isTrue();
        PasswordBasedEncryption pbe = (PasswordBasedEncryption) macOptional.get();

        assertThat(pbe.getDigest()).isEmpty();
        assertThat(pbe.getEncryptionAlgorithm()).isEmpty();
        assertThat(pbe.getPseudoRandomFunction()).isPresent();

        Optional<Mac> mac = pbe.getPseudoRandomFunction();
        assertThat(mac).isPresent();
        assertThat(mac.get().getName()).isEqualTo("HmacSHA256");
        assertThat(mac.get().hasChildren()).isTrue();

        Map<Class<? extends INode>, INode> children = mac.get().getChildren();
        assertThat(children).hasSize(2);
        INode child = children.get(MessageDigest.class);

        assertThat(child.is(MessageDigest.class)).isTrue();
        MessageDigest messageDigest = (MessageDigest) child;
        assertThat(messageDigest.getName()).isEqualTo("SHA-256");
        assertThat(messageDigest.getDefaultKeyLength()).isPresent();
        assertThat(messageDigest.getDefaultKeyLength().get().asString()).isEqualTo("256");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(256);
        assertThat(messageDigest.getBlockSize()).isPresent();
        assertThat(messageDigest.getBlockSize().get().getValue()).isEqualTo(512);
    }

    @Test
    void configuration() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaMacMapper jcaMacMapper = new JcaMacMapper();
        Optional<Algorithm> macOptional =
                jcaMacMapper.parse("PBEWithHmacSHA256", testDetectionLocation, new TestConfig());

        assertThat(macOptional).isPresent();
        assertThat(macOptional.get().is(PasswordBasedEncryption.class)).isTrue();
        PasswordBasedEncryption pbe = (PasswordBasedEncryption) macOptional.get();

        assertThat(pbe.getDigest()).isEmpty();
        assertThat(pbe.getEncryptionAlgorithm()).isEmpty();
        assertThat(pbe.getPseudoRandomFunction()).isPresent();

        Optional<Mac> mac = pbe.getPseudoRandomFunction();
        assertThat(mac).isPresent();
        assertThat(mac.get().getName()).isEqualTo("hmacsha256");
        assertThat(mac.get().hasChildren()).isTrue();

        Map<Class<? extends INode>, INode> children = mac.get().getChildren();
        assertThat(children).hasSize(2);
        INode child = children.get(MessageDigest.class);

        assertThat(child.is(MessageDigest.class)).isTrue();
        MessageDigest messageDigest = (MessageDigest) child;
        assertThat(messageDigest.getName()).isEqualTo("sha-256");
        assertThat(messageDigest.getDefaultKeyLength()).isPresent();
        assertThat(messageDigest.getDefaultKeyLength().get().asString()).isEqualTo("256");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(256);
        assertThat(messageDigest.getBlockSize()).isPresent();
        assertThat(messageDigest.getBlockSize().get().getValue()).isEqualTo(512);
    }
}
