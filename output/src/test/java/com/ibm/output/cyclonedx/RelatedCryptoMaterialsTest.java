/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2025 IBM
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
import com.ibm.mapper.model.InitializationVectorLength;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.padding.PKCS5;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptoMaterialProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.RelatedCryptoMaterialType;
import org.junit.jupiter.api.Test;

class RelatedCryptoMaterialsTest extends TestBase {

    @Test
    void tag() {
        this.assertsNode(
                () -> {
                    final AES aes =
                            new AES(
                                    AuthenticatedEncryption.class,
                                    new AES(128, new GCM(detectionLocation), detectionLocation));
                    aes.put(new Oid("2.16.840.1.101.3.4.1.6", detectionLocation));
                    aes.put(new TagLength(128, detectionLocation));
                    final SecretKey secretKey = new SecretKey(aes);
                    secretKey.put(new KeyGeneration(detectionLocation));
                    secretKey.put(new Decrypt(detectionLocation));
                    return secretKey;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(3);

                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (cryptoProperties
                                .getAssetType()
                                .equals(AssetType.RELATED_CRYPTO_MATERIAL)) {
                            assertThat(cryptoProperties.getRelatedCryptoMaterialProperties())
                                    .isNotNull();
                            final RelatedCryptoMaterialProperties relatedCryptoMaterialProperties =
                                    cryptoProperties.getRelatedCryptoMaterialProperties();
                            if (relatedCryptoMaterialProperties
                                    .getType()
                                    .equals(RelatedCryptoMaterialType.TAG)) {
                                assertThat(relatedCryptoMaterialProperties.getSize())
                                        .isEqualTo(128);
                            } else {
                                assertThat(relatedCryptoMaterialProperties.getType())
                                        .isEqualTo(RelatedCryptoMaterialType.SECRET_KEY);
                            }
                        }
                    }
                });
    }

    @Test
    void iv() {
        this.assertsNode(
                () -> {
                    final AES aes =
                            new AES(
                                    128,
                                    new CBC(detectionLocation),
                                    new PKCS5(detectionLocation),
                                    detectionLocation);
                    aes.put(new InitializationVectorLength(128, detectionLocation));
                    return aes;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(2);

                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (cryptoProperties
                                .getAssetType()
                                .equals(AssetType.RELATED_CRYPTO_MATERIAL)) {
                            assertThat(cryptoProperties.getRelatedCryptoMaterialProperties())
                                    .isNotNull();
                            final RelatedCryptoMaterialProperties relatedCryptoMaterialProperties =
                                    cryptoProperties.getRelatedCryptoMaterialProperties();
                            assertThat(relatedCryptoMaterialProperties.getType())
                                    .isEqualTo(RelatedCryptoMaterialType.INITIALIZATION_VECTOR);
                            assertThat(relatedCryptoMaterialProperties.getSize()).isEqualTo(128);
                        }
                    }
                });
    }

    @Test
    void pbe() {
        this.assertsNode(
                () -> {
                    final PBKDF2 pbkdf2 = new PBKDF2(new HMAC(new SHA(detectionLocation)));
                    final SecretKey secretKey = new SecretKey(pbkdf2);
                    secretKey.put(new PasswordLength(32, detectionLocation));
                    secretKey.put(new KeyLength(1024, detectionLocation));
                    secretKey.put(new SaltLength(192, detectionLocation));
                    return secretKey;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(6);

                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (cryptoProperties
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
                            } else if (relatedCryptoMaterialProperties
                                    .getType()
                                    .equals(RelatedCryptoMaterialType.SALT)) {
                                assertThat(relatedCryptoMaterialProperties.getSize())
                                        .isEqualTo(192);
                            } else {
                                assertThat(relatedCryptoMaterialProperties.getType())
                                        .isEqualTo(RelatedCryptoMaterialType.SECRET_KEY);
                            }
                        }
                    }
                });
    }
}
