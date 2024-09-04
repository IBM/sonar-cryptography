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

import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.mode.GCM;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.RelatedCryptoMaterialType;
import org.junit.jupiter.api.Test;

class KeyTest extends TestBase {

    @Test
    void base() {
        this.assertsNode(
                () -> new PublicKey((PublicKeyEncryption) new RSA(detectionLocation)),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    assertThat(bom.getComponents())
                            .anyMatch(
                                    component -> {
                                        asserts(component.getEvidence());
                                        CryptoProperties c = component.getCryptoProperties();
                                        return component.getName().equals("RSA")
                                                && c.getRelatedCryptoMaterialProperties()
                                                        .getType()
                                                        .equals(
                                                                RelatedCryptoMaterialType
                                                                        .PUBLIC_KEY);
                                    });
                });
    }

    @Test
    void secretKey() {
        this.assertsNode(
                () -> {
                    final AES aes =
                            new AES(
                                    AuthenticatedEncryption.class,
                                    new AES(128, new GCM(detectionLocation), detectionLocation));
                    aes.put(new Oid("2.16.840.1.101.3.4.1.6", detectionLocation));
                    final SecretKey secretKey = new SecretKey(aes);
                    secretKey.put(new KeyGeneration(detectionLocation));
                    secretKey.put(new Encrypt(detectionLocation));
                    secretKey.put(new Decrypt(detectionLocation));
                    return secretKey;
                },
                bom -> {});
    }
}
