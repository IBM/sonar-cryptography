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
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaPasswordBasedEncryptionMapperTest {

    @Test
    void base() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaPasswordBasedEncryptionMapper jcaPasswordBasedEncryptionMapper =
                new JcaPasswordBasedEncryptionMapper();
        Optional<PasswordBasedEncryption> pbeOpt =
                jcaPasswordBasedEncryptionMapper.parse(
                        "PBEWithHmacSHA256AndAES", testDetectionLocation, Configuration.DEFAULT);

        assertThat(pbeOpt).isPresent();
        PasswordBasedEncryption pbe = pbeOpt.get();
        assertThat(pbe.getName()).isEqualTo("PBEWithHmacSHA256AndAES");

        assertThat(pbe.getChildren()).hasSize(2);
        assertThat(pbe.getDigest()).isEmpty();
        assertThat(pbe.getPseudoRandomFunction()).isPresent();
        Mac mac = pbe.getPseudoRandomFunction().get();

        assertThat(mac.getName()).isEqualTo("HmacSHA256");
        assertThat(mac.getChildren()).hasSize(2);

        assertThat(pbe.getEncryptionAlgorithm()).isPresent();
        Algorithm algorithm = pbe.getEncryptionAlgorithm().get();

        assertThat(algorithm.hasChildren()).isTrue();
        assertThat(algorithm.getDefaultKeyLength()).isPresent();
        assertThat(algorithm.getDefaultKeyLength().get().asString()).isEqualTo("128");
    }
}
