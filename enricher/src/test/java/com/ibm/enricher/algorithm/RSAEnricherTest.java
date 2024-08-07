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
package com.ibm.enricher.algorithm;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.enricher.TestBase;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class RSAEnricherTest extends TestBase {

    @Test
    void oid() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");
        final RSA rsa = new RSA(testDetectionLocation);
        this.logBefore(rsa);

        final RSAEnricher rsaEnricher = new RSAEnricher();
        final INode enriched = rsaEnricher.enrich(rsa);
        this.logAfter(enriched);

        assertThat(enriched.is(PublicKeyEncryption.class)).isTrue();
        assertThat(enriched).isInstanceOf(RSA.class);
        final RSA enrichedRSA = (RSA) enriched;
        assertThat(enrichedRSA.hasChildOfType(Oid.class)).isPresent();
        assertThat(enrichedRSA.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("1.2.840.113549.1.1.1");
    }

    @Test
    void defaultKeyLengthForJca() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "Jca");
        final RSA rsa = new RSA(testDetectionLocation);
        this.logBefore(rsa);

        final RSAEnricher rsaEnricher = new RSAEnricher();
        final INode enriched = rsaEnricher.enrich(rsa);
        this.logAfter(enriched);

        assertThat(enriched.is(PublicKeyEncryption.class)).isTrue();
        assertThat(enriched).isInstanceOf(RSA.class);
        final RSA enrichedRSA = (RSA) enriched;
        assertThat(enrichedRSA.getKeyLength()).isPresent();
        assertThat(enrichedRSA.getKeyLength().get().asString()).isEqualTo("2048");
    }
}
