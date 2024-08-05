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

import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.algorithms.x448;
import com.ibm.mapper.utils.DetectionLocation;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class JcaKeyAgreementMapperTest {

    @Test
    void base() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaKeyAgreementMapper jcaKeyAgreementMapperTest = new JcaKeyAgreementMapper();
        Optional<KeyAgreement> keyAgreementOptional =
                jcaKeyAgreementMapperTest.parse("X448", testDetectionLocation);

        assertThat(keyAgreementOptional).isPresent();
        assertThat(keyAgreementOptional.get()).isInstanceOf(x448.class);
        assertThat(keyAgreementOptional.get().is(KeyAgreement.class)).isTrue();
    }
}
