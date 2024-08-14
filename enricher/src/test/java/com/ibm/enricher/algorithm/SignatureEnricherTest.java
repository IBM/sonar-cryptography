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
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class SignatureEnricherTest extends TestBase {

    @Test
    void shaAndDSA() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");
        final DSA dsa = new DSA(testDetectionLocation);
        dsa.put(new SHA2(384, testDetectionLocation));
        this.logBefore(dsa);

        final SignatureEnricher signatureEnricher = new SignatureEnricher();
        final INode enriched = signatureEnricher.enrich(dsa);
        this.logAfter(enriched);

        assertThat(dsa.hasChildOfType(Oid.class)).isPresent();
        assertThat(dsa.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("2.16.840.1.101.3.4.3.3");
    }

    @Test
    void shaAndECDSA() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");
        final ECDSA ecdsa = new ECDSA(testDetectionLocation);
        ecdsa.put(new SHA3(384, testDetectionLocation));
        this.logBefore(ecdsa);

        final SignatureEnricher signatureEnricher = new SignatureEnricher();
        final INode enriched = signatureEnricher.enrich(ecdsa);
        this.logAfter(enriched);

        assertThat(ecdsa.hasChildOfType(Oid.class)).isPresent();
        assertThat(ecdsa.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("2.16.840.1.101.3.4.3.11");
    }

    @Test
    void shaAndRSA() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");
        final RSA rsa = new RSA(Signature.class, testDetectionLocation);
        rsa.put(new SHA2(224, new SHA2(512, testDetectionLocation), testDetectionLocation));
        this.logBefore(rsa);

        final SignatureEnricher signatureEnricher = new SignatureEnricher();
        final INode enriched = signatureEnricher.enrich(rsa);
        this.logAfter(enriched);

        assertThat(rsa.hasChildOfType(Oid.class)).isPresent();
        assertThat(rsa.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("1.2.840.113549.1.1.15");
    }
}
