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
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.jca.JcaAlgorithmMapper;
import com.ibm.mapper.model.*;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.cyclondx.CBOMOutputFile;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

class AlgorithmTest {

    private final String filePath = "test.java";

    @Test
    void baseRSA() {
        final DetectionLocation detectionLocation =
                new DetectionLocation(filePath, 1, 1, Collections.emptyList());
        final Algorithm algorithm = new Algorithm("RSA", detectionLocation);

        final CBOMOutputFile outputFile = new CBOMOutputFile();
        outputFile.add(List.of(algorithm));
        final Bom bom = outputFile.getBom();

        assertThat(bom.getComponents()).hasSize(1);
        Component component = bom.getComponents().get(0);
        assertThat(component.getName()).isEqualTo("rsa");

        CryptoProperties cryptoProperties = component.getCryptoProperties();
        assertThat(cryptoProperties.getAssetType()).isEqualTo(AssetType.ALGORITHM);

        assertThat(component.getEvidence().getOccurrences()).hasSize(1);
        final Occurrence occurrence = component.getEvidence().getOccurrences().get(0);
        assertThat(occurrence.getLocation()).isEqualTo(filePath);
        assertThat(occurrence.getLine()).isEqualTo(1);
        assertThat(occurrence.getOffset()).isEqualTo(1);
        assertThat(occurrence.getAdditionalContext()).isNull();

        AlgorithmProperties algorithmProperties =
                component.getCryptoProperties().getAlgorithmProperties();
        assertThat(algorithmProperties.getParameterSetIdentifier()).isNull();
    }

    @Test
    void RSAwithKeyLength() {
        final DetectionLocation detectionLocation =
                new DetectionLocation(filePath, 1, 1, Collections.emptyList());
        JcaAlgorithmMapper algorithmMapper = new JcaAlgorithmMapper();
        Optional<? extends INode> algorithmOptional =
                algorithmMapper.parse("RSA", detectionLocation, Configuration.DEFAULT);
        assertThat(algorithmOptional).isPresent();
        assertThat(algorithmOptional.get().is(Algorithm.class)).isTrue();

        final CBOMOutputFile outputFile = new CBOMOutputFile();
        outputFile.add(List.of(algorithmOptional.get()));
        final Bom bom = outputFile.getBom();

        assertThat(bom.getComponents()).hasSize(1);
        Component component = bom.getComponents().get(0);
        assertThat(component.getName()).isEqualTo("rsa-2048");

        CryptoProperties cryptoProperties = component.getCryptoProperties();
        assertThat(cryptoProperties.getAssetType()).isEqualTo(AssetType.ALGORITHM);

        assertThat(component.getEvidence().getOccurrences()).hasSize(1);
        final Occurrence occurrence = component.getEvidence().getOccurrences().get(0);
        assertThat(occurrence.getLocation()).isEqualTo(filePath);
        assertThat(occurrence.getLine()).isEqualTo(1);
        assertThat(occurrence.getOffset()).isEqualTo(1);
        assertThat(occurrence.getAdditionalContext()).isNull();

        AlgorithmProperties algorithmProperties =
                component.getCryptoProperties().getAlgorithmProperties();
        assertThat(algorithmProperties.getParameterSetIdentifier()).isEqualTo("2048");
    }

    @Test
    void algorithmWithMultipleCryptoFunctions() {
        final CBOMOutputFile outputFile = new CBOMOutputFile();
        final DetectionLocation detectionLocation =
                new DetectionLocation(filePath, 1, 1, Collections.emptyList());

        final Algorithm algorithm = new Algorithm("RSA", detectionLocation);
        final KeyGeneration keyGeneration = new KeyGeneration(detectionLocation);
        algorithm.append(keyGeneration);
        final Encrypt encrypt = new Encrypt(detectionLocation);
        algorithm.append(encrypt);

        outputFile.add(List.of(algorithm));

        final Bom bom = outputFile.getBom();

        assertThat(bom.getComponents()).hasSize(1);
        Component component = bom.getComponents().get(0);
        assertThat(component.getName()).isEqualTo("rsa");

        CryptoProperties cryptoProperties = component.getCryptoProperties();
        AlgorithmProperties algorithmProperties = cryptoProperties.getAlgorithmProperties();
        assertThat(algorithmProperties.getCryptoFunctions()).hasSize(2);
        assertThat(algorithmProperties.getCryptoFunctions())
                .anyMatch(func -> func.equals(CryptoFunction.KEYGEN));
        assertThat(algorithmProperties.getCryptoFunctions())
                .anyMatch(func -> func.equals(CryptoFunction.ENCRYPT));
    }

    @Test
    void pbkdfWithSaltAndPassword() {
        final DetectionLocation detectionLocation =
                new DetectionLocation(filePath, 1, 1, Collections.emptyList());
        final Algorithm algorithm = new Algorithm("PBKDF2WithHmacSHA1", detectionLocation);
        final SaltLength saltLength = new SaltLength(192, detectionLocation);
        final PasswordLength passwordLength = new PasswordLength(32, detectionLocation);
        final KeyLength keyLength = new KeyLength(1024, detectionLocation);
        final PasswordBasedKeyDerivationFunction pbkdf =
                new PasswordBasedKeyDerivationFunction(algorithm, detectionLocation);
        pbkdf.append(saltLength);
        pbkdf.append(passwordLength);
        pbkdf.append(keyLength);

        final CBOMOutputFile outputFile = new CBOMOutputFile();
        outputFile.add(List.of(pbkdf));

        final Bom bom = outputFile.getBom();

        assertThat(bom.getComponents()).hasSize(3);
    }
}
