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
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaBasePaddingMapperTest {

    @Test
    void base() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaBasePaddingMapper jcaBasePaddingMapper = new JcaBasePaddingMapper();
        Optional<Padding> paddingOptional =
                jcaBasePaddingMapper.parse(
                        "PKCS1Padding", testDetectionLocation, Configuration.DEFAULT);

        assertThat(paddingOptional).isPresent();
        assertThat(paddingOptional.get().getName()).isEqualTo("PKCS1");
        assertThat(paddingOptional.get().is(Padding.class)).isTrue();
        assertThat(paddingOptional.get().hasChildren()).isFalse();
    }

    @Test
    void configuration() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaBasePaddingMapper jcaBasePaddingMapper = new JcaBasePaddingMapper();
        Optional<Padding> paddingOptional =
                jcaBasePaddingMapper.parse("PKCS1Padding", testDetectionLocation, new TestConfig());

        assertThat(paddingOptional).isPresent();
        assertThat(paddingOptional.get().getName()).isEqualTo("pkcs1");
        assertThat(paddingOptional.get().is(Padding.class)).isTrue();
        assertThat(paddingOptional.get().hasChildren()).isFalse();
    }
}
