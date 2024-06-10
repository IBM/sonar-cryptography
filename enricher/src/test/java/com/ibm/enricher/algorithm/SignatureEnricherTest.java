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

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.jca.JcaSignatureMapper;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class SignatureEnricherTest {

    @Test
    void SHA256withDSATest() {
        final DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        final JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        final Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse(
                        "SHA256withDSA", testDetectionLocation, Configuration.DEFAULT);

        assertThat(signatureOptional).isPresent();
        final Signature signature = signatureOptional.get();

        SignatureEnricher signatureEnricher = new SignatureEnricher();
        signatureEnricher.enrich(signature, Map.of());

        assertThat(signature.hasChildOfType(Oid.class)).isPresent();
    }

    @Test
    void RSASSA_PSS() {
        final DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        final JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        final Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse(
                        "RSASSA-PSS", testDetectionLocation, Configuration.DEFAULT);

        assertThat(signatureOptional).isPresent();
        final Signature signature = signatureOptional.get();

        SignatureEnricher signatureEnricher = new SignatureEnricher();
        signatureEnricher.enrich(signature, Map.of());

        assertThat(signature.hasChildOfType(Oid.class)).isPresent();
    }

    @Test
    void MD5withRSATest() {
        final DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        final JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        final Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse(
                        "MD5withRSA", testDetectionLocation, Configuration.DEFAULT);

        assertThat(signatureOptional).isPresent();
        final Signature signature = signatureOptional.get();

        SignatureEnricher signatureEnricher = new SignatureEnricher();
        signatureEnricher.enrich(signature, Map.of());

        assertThat(signature.hasChildOfType(Oid.class)).isPresent();
    }
}
