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

import org.junit.jupiter.api.Test;

class JcaEllipticCurveAlgorithmMapperTest {

    @Test
    void base() {
        /*DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaEllipticCurveMapper jcaEllipticCurveMapper = new JcaEllipticCurveMapper();
        Optional<Algorithm> ellipticCurveOptional =
                jcaEllipticCurveMapper.parse("X448", testDetectionLocation, Configuration.DEFAULT);

        assertThat(ellipticCurveOptional).isPresent();
        assertThat(ellipticCurveOptional.get().getName()).isEqualTo("X448");
        assertThat(((KeyAgreement) ellipticCurveOptional.get()).hasChildOfType(EllipticCurve.class))
                .isPresent();
        assertThat(
                        ((KeyAgreement) ellipticCurveOptional.get())
                                .hasChildOfType(EllipticCurve.class)
                                .get()
                                .asString())
                .isEqualTo("curve448");*/
    }
}
