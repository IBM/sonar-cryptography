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
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaSignatureMapperTest {

    @Test
    void NONEwithRSA() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse(
                        "NONEwithRSA", testDetectionLocation, Configuration.DEFAULT);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get().getName()).isEqualTo("NONEwithRSA");
        assertThat(signatureOptional.get().getFormat()).isEmpty();
        assertThat(signatureOptional.get().getDigest()).isEmpty();
        assertThat(signatureOptional.get().getMGF()).isEmpty();
        assertThat(signatureOptional.get().getSignatureAlgorithm()).isPresent();

        Algorithm signatureAlgo = signatureOptional.get().getSignatureAlgorithm().get();
        assertThat(signatureAlgo.getName()).isEqualTo("RSA");
        assertThat(signatureAlgo.getDefaultKeyLength()).isPresent();
        assertThat(signatureAlgo.getDefaultKeyLength().get().asString()).isEqualTo("2048");
    }

    @Test
    void SHA384withDSA() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse(
                        "SHA384withDSA", testDetectionLocation, Configuration.DEFAULT);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get().getName()).isEqualTo("SHA384withDSA");
        assertThat(signatureOptional.get().getFormat()).isEmpty();
        assertThat(signatureOptional.get().getMGF()).isEmpty();

        assertThat(signatureOptional.get().getDigest()).isPresent();
        MessageDigest messageDigest = signatureOptional.get().getDigest().get();
        assertThat(messageDigest.getName()).isEqualTo("SHA-384");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(384);

        assertThat(signatureOptional.get().getSignatureAlgorithm()).isPresent();
        Algorithm signatureAlgo = signatureOptional.get().getSignatureAlgorithm().get();
        assertThat(signatureAlgo.getName()).isEqualTo("DSA");
    }

    @Test
    void SHA3_224withECDSA() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse(
                        "SHA3-224withECDSA", testDetectionLocation, Configuration.DEFAULT);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get().getName()).isEqualTo("SHA3-224withECDSA");
        assertThat(signatureOptional.get().getFormat()).isEmpty();
        assertThat(signatureOptional.get().getMGF()).isEmpty();

        assertThat(signatureOptional.get().getDigest()).isPresent();
        MessageDigest messageDigest = signatureOptional.get().getDigest().get();
        assertThat(messageDigest.getName()).isEqualTo("SHA3-224");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(224);

        assertThat(signatureOptional.get().getSignatureAlgorithm()).isPresent();
        Algorithm signatureAlgo = signatureOptional.get().getSignatureAlgorithm().get();
        assertThat(signatureAlgo.getName()).isEqualTo("ECDSA");
    }

    @Test
    void SHA1withDSAinP1363Format() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse(
                        "SHA1withDSAinP1363Format", testDetectionLocation, Configuration.DEFAULT);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get().getName()).isEqualTo("SHA1withDSAinP1363Format");
        assertThat(signatureOptional.get().getFormat()).isPresent();
        assertThat(signatureOptional.get().getFormat().get().getValue()).isEqualTo("P1363Format");

        assertThat(signatureOptional.get().getDigest()).isPresent();
        MessageDigest messageDigest = signatureOptional.get().getDigest().get();
        assertThat(messageDigest.getName()).isEqualTo("SHA-1");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(160);

        assertThat(signatureOptional.get().getSignatureAlgorithm()).isPresent();
        Algorithm signatureAlgo = signatureOptional.get().getSignatureAlgorithm().get();
        assertThat(signatureAlgo.getName()).isEqualTo("DSA");
    }

    @Test
    void MD5withRSAandMGF1() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse(
                        "MD5withRSAandMGF1", testDetectionLocation, Configuration.DEFAULT);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get().getName()).isEqualTo("MD5withRSAandMGF1");
        assertThat(signatureOptional.get().getFormat()).isEmpty();

        assertThat(signatureOptional.get().getDigest()).isPresent();
        MessageDigest messageDigest = signatureOptional.get().getDigest().get();
        assertThat(messageDigest.getName()).isEqualTo("MD5");

        assertThat(signatureOptional.get().getSignatureAlgorithm()).isPresent();
        Algorithm signatureAlgo = signatureOptional.get().getSignatureAlgorithm().get();
        assertThat(signatureAlgo.getName()).isEqualTo("RSA");

        assertThat(signatureOptional.get().getMGF()).isPresent();
        MaskGenerationFunction mgf = signatureOptional.get().getMGF().get();
        assertThat(mgf.getName()).isEqualTo("MGF1");
    }

    @Test
    void RSASSA_PSS() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse(
                        "RSASSA-PSS", testDetectionLocation, Configuration.DEFAULT);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get().getName()).isEqualTo("RSASSA-PSS");
        assertThat(signatureOptional.get().getFormat()).isEmpty();
        assertThat(signatureOptional.get().getMGF()).isEmpty();

        assertThat(signatureOptional.get().getSignatureAlgorithm()).isPresent();
        Algorithm signatureAlgo = signatureOptional.get().getSignatureAlgorithm().get();
        assertThat(signatureAlgo.getName()).isEqualTo("RSA");

        assertThat(signatureOptional.get().isProbabilisticSignatureScheme()).isTrue();
    }
}
