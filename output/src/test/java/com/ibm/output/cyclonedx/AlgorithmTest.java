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

import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptoMaterialProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.cyclonedx.model.component.crypto.enums.RelatedCryptoMaterialType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AlgorithmTest extends TestBase {

    @Test
    void baseRSA() {
        this.assertsNode(
                () -> new RSA(detectionLocation),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    Component component = bom.getComponents().get(0);
                    assertThat(component.getName()).isEqualTo("RSA");

                    CryptoProperties cryptoProperties = component.getCryptoProperties();
                    assertThat(cryptoProperties.getAssetType()).isEqualTo(AssetType.ALGORITHM);

                    asserts(component.getEvidence());

                    AlgorithmProperties algorithmProperties =
                            component.getCryptoProperties().getAlgorithmProperties();
                    assertThat(algorithmProperties.getParameterSetIdentifier()).isNull();
                });
    }

    @Test
    void algorithmWithMultipleCryptoFunctions() {
        this.assertsNode(
                () -> {
                    final RSA rsa = new RSA(detectionLocation);
                    rsa.put(new KeyGeneration(detectionLocation));
                    rsa.put(new Encrypt(detectionLocation));
                    return rsa;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    Component component = bom.getComponents().get(0);
                    assertThat(component.getName()).isEqualTo("RSA");

                    CryptoProperties cryptoProperties = component.getCryptoProperties();
                    assertThat(cryptoProperties.getAssetType()).isEqualTo(AssetType.ALGORITHM);

                    asserts(component.getEvidence());

                    AlgorithmProperties algorithmProperties =
                            component.getCryptoProperties().getAlgorithmProperties();
                    assertThat(algorithmProperties.getCryptoFunctions()).hasSize(2);
                    assertThat(algorithmProperties.getCryptoFunctions())
                            .contains(CryptoFunction.ENCRYPT, CryptoFunction.KEYGEN);
                });
    }

    @Test
    void pbkdfWithSaltAndPassword() {
        this.assertsNode(
                () -> {
                    final PasswordBasedKeyDerivationFunction pbkdf =
                            new PBKDF2(new SHA(detectionLocation));
                    final SaltLength saltLength = new SaltLength(192, detectionLocation);
                    final PasswordLength passwordLength = new PasswordLength(32, detectionLocation);
                    final KeyLength keyLength = new KeyLength(1024, detectionLocation);
                    pbkdf.put(saltLength);
                    pbkdf.put(passwordLength);
                    pbkdf.put(keyLength);
                    return pbkdf;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(4);
                    assertThat(bom.getComponents().stream().map(Component::getName))
                            .contains("PBKDF2-SHA1", "SHA1");

                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (component.getName().equalsIgnoreCase("PBKDF2-SHA1")) {
                            assertThat(cryptoProperties.getAssetType())
                                    .isEqualTo(AssetType.ALGORITHM);
                            assertThat(cryptoProperties.getAlgorithmProperties()).isNotNull();
                            final AlgorithmProperties algorithmProperties =
                                    cryptoProperties.getAlgorithmProperties();
                            assertThat(algorithmProperties.getPrimitive()).isEqualTo(Primitive.KDF);
                            assertThat(algorithmProperties.getParameterSetIdentifier())
                                    .isEqualTo("1024");
                        } else if (component.getName().equalsIgnoreCase("SHA1")) {
                            assertThat(cryptoProperties.getAssetType())
                                    .isEqualTo(AssetType.ALGORITHM);
                            assertThat(cryptoProperties.getAlgorithmProperties()).isNotNull();
                            final AlgorithmProperties algorithmProperties =
                                    cryptoProperties.getAlgorithmProperties();
                            assertThat(algorithmProperties.getPrimitive())
                                    .isEqualTo(Primitive.HASH);
                            assertThat(algorithmProperties.getParameterSetIdentifier())
                                    .isEqualTo("160");
                        } else if (cryptoProperties
                                .getAssetType()
                                .equals(AssetType.RELATED_CRYPTO_MATERIAL)) {
                            assertThat(cryptoProperties.getRelatedCryptoMaterialProperties())
                                    .isNotNull();
                            final RelatedCryptoMaterialProperties relatedCryptoMaterialProperties =
                                    cryptoProperties.getRelatedCryptoMaterialProperties();
                            if (relatedCryptoMaterialProperties
                                    .getType()
                                    .equals(RelatedCryptoMaterialType.PASSWORD)) {
                                assertThat(relatedCryptoMaterialProperties.getSize()).isEqualTo(32);
                            } else {
                                assertThat(relatedCryptoMaterialProperties.getSize())
                                        .isEqualTo(192);
                            }
                        }
                    }
                });
    }

    @Test
    void signature() {
        this.assertsNode(() -> {
            final DSA dsa = new DSA(detectionLocation);
            dsa.put(new Oid("2.16.840.1.101.3.4.3.2", detectionLocation));
            final SHA2 sha256 = new SHA2(256, detectionLocation);
            sha256.put(new Digest(detectionLocation));
            sha256.put(new Oid("2.16.840.1.101.3.4.2.1", detectionLocation));
            dsa.put(sha256);
            final PrivateKey privateKey = new PrivateKey(dsa);
            privateKey.put(new Sign(detectionLocation));
            privateKey.put(new KeyGeneration(detectionLocation));
            privateKey.put(new KeyLength(1024, detectionLocation));
            return privateKey;
        }, bom -> {

        });
    }
}
