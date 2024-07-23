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
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.OptimalAsymmetricEncryptionPadding;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaOAEPPaddingMapperTest {

    @Test
    void base() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaOAEPPaddingMapper jcaOAEPPaddingMapper = new JcaOAEPPaddingMapper();
        Optional<OptimalAsymmetricEncryptionPadding> oaepPAdding =
                jcaOAEPPaddingMapper.parse(
                        "OAEPWithMD5AndMGF1Padding", testDetectionLocation, Configuration.DEFAULT);

        assertThat(oaepPAdding).isPresent();
        assertThat(oaepPAdding.get().is(OptimalAsymmetricEncryptionPadding.class)).isTrue();
        OptimalAsymmetricEncryptionPadding oaep = oaepPAdding.get();

        Optional<MessageDigest> messageDigestOptional = oaep.getDigest();
        assertThat(messageDigestOptional).isPresent();
        assertThat(messageDigestOptional.get().getName()).isEqualTo("MD5");
        assertThat(messageDigestOptional.get().getKind()).isEqualTo(MessageDigest.class);

        Optional<MaskGenerationFunction> maskGenerationFunctionOptional = oaep.getMGF();
        assertThat(maskGenerationFunctionOptional).isPresent();
        assertThat(maskGenerationFunctionOptional.get().getName()).isEqualTo("MGF1");
        assertThat(maskGenerationFunctionOptional.get().is(MaskGenerationFunction.class)).isTrue();
    }

    @Test
    void oaepDefault() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaOAEPPaddingMapper jcaOAEPPaddingMapper = new JcaOAEPPaddingMapper();
        Optional<OptimalAsymmetricEncryptionPadding> oaepPAdding =
                jcaOAEPPaddingMapper.parse(
                        "OAEPPadding", testDetectionLocation, Configuration.DEFAULT);

        assertThat(oaepPAdding).isPresent();
        assertThat(oaepPAdding.get().is(OptimalAsymmetricEncryptionPadding.class)).isTrue();
        assertThat(oaepPAdding.get().getName()).isEqualTo("OAEP");
        assertThat(oaepPAdding.get().hasChildren()).isFalse();
    }

    @Test
    void configuration() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaOAEPPaddingMapper jcaOAEPPaddingMapper = new JcaOAEPPaddingMapper();
        Optional<OptimalAsymmetricEncryptionPadding> oaepPAdding =
                jcaOAEPPaddingMapper.parse(
                        "OAEPWithMD5AndMGF1Padding", testDetectionLocation, new TestConfig());

        assertThat(oaepPAdding).isPresent();
        assertThat(oaepPAdding.get().is(OptimalAsymmetricEncryptionPadding.class)).isTrue();
        OptimalAsymmetricEncryptionPadding oaep = oaepPAdding.get();

        Optional<MessageDigest> messageDigestOptional = oaep.getDigest();
        assertThat(messageDigestOptional).isPresent();
        assertThat(messageDigestOptional.get().getName()).isEqualTo("md5");
        assertThat(messageDigestOptional.get().getKind()).isEqualTo(MessageDigest.class);

        Optional<MaskGenerationFunction> maskGenerationFunctionOptional = oaep.getMGF();
        assertThat(maskGenerationFunctionOptional).isPresent();
        assertThat(maskGenerationFunctionOptional.get().getName()).isEqualTo("mgf1");
        assertThat(maskGenerationFunctionOptional.get().is(MaskGenerationFunction.class)).isTrue();
    }
}
