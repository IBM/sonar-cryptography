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
package com.ibm.output.cyclondx.builder;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.InitializationVectorLength;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.NonceLength;
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.SecretKey;
import java.util.List;
import java.util.UUID;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptoMaterialProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.RelatedCryptoMaterialType;
import org.cyclonedx.model.component.evidence.Occurrence;

public class RelatedCryptoMaterialComponentBuilder
        implements IRelatedCryptoMaterialComponentBuilder {

    @Nonnull private final Component component;
    @Nonnull private final CryptoProperties cryptoProperties;
    @Nonnull private final RelatedCryptoMaterialProperties relatedCryptoMaterialProperties;

    @Nonnull private UUID uuid = UUID.randomUUID();

    protected RelatedCryptoMaterialComponentBuilder() {
        this.component = new Component();
        this.cryptoProperties = new CryptoProperties();
        this.relatedCryptoMaterialProperties = new RelatedCryptoMaterialProperties();
    }

    public RelatedCryptoMaterialComponentBuilder(
            @Nonnull Component component,
            @Nonnull CryptoProperties cryptoProperties,
            @Nonnull RelatedCryptoMaterialProperties relatedCryptoMaterialProperties,
            @Nonnull UUID uuid) {
        this.component = component;
        this.cryptoProperties = cryptoProperties;
        this.relatedCryptoMaterialProperties = relatedCryptoMaterialProperties;
        this.uuid = uuid;
    }

    @Nonnull
    public static IRelatedCryptoMaterialComponentBuilder create() {
        return new RelatedCryptoMaterialComponentBuilder();
    }

    @Nonnull
    @Override
    public IRelatedCryptoMaterialComponentBuilder name(@Nullable INode name) {
        if (name == null) {
            return new RelatedCryptoMaterialComponentBuilder(
                    component, cryptoProperties, relatedCryptoMaterialProperties, uuid);
        }

        final StringBuilder stringBuilder = new StringBuilder();
        if (name instanceof SaltLength) {
            stringBuilder.append("salt");
        } else if (name instanceof PasswordLength) {
            stringBuilder.append("password");
        } else if (name instanceof PrivateKey) {
            stringBuilder.append("private-key");
        } else if (name instanceof PublicKey) {
            stringBuilder.append("public-key");
        } else if (name instanceof SecretKey) {
            stringBuilder.append("secret-key");
        } else if (name instanceof Key) {
            stringBuilder.append("key");
        } else if (name instanceof NonceLength) {
            stringBuilder.append("nonce");
        } else if (name instanceof InitializationVectorLength) {
            stringBuilder.append("iv");
        }
        stringBuilder.append("@").append(this.uuid);
        this.component.setName(stringBuilder.toString());

        return new RelatedCryptoMaterialComponentBuilder(
                component, cryptoProperties, relatedCryptoMaterialProperties, uuid);
    }

    @Nonnull
    @Override
    public IRelatedCryptoMaterialComponentBuilder type(@Nullable INode type) {
        if (type == null) {
            return new RelatedCryptoMaterialComponentBuilder(
                    component, cryptoProperties, relatedCryptoMaterialProperties, uuid);
        }

        RelatedCryptoMaterialType types = null;
        if (type instanceof SaltLength) {
            types = RelatedCryptoMaterialType.SALT;
        } else if (type instanceof PasswordLength) {
            types = RelatedCryptoMaterialType.PASSWORD;
        } else if (type.is(SecretKey.class) || type.is(Key.class)) {
            types = RelatedCryptoMaterialType.SECRET_KEY;
        } else if (type.is(PrivateKey.class)) {
            types = RelatedCryptoMaterialType.PRIVATE_KEY;
        } else if (type.is(PublicKey.class)) {
            types = RelatedCryptoMaterialType.PUBLIC_KEY;
        } else if (type instanceof NonceLength) {
            types = RelatedCryptoMaterialType.NONCE;
        } else if (type instanceof InitializationVectorLength) {
            types = RelatedCryptoMaterialType.INITIALIZATION_VECTOR;
        }

        if (types != null) {
            this.relatedCryptoMaterialProperties.setType(types);
        }

        return new RelatedCryptoMaterialComponentBuilder(
                component, cryptoProperties, relatedCryptoMaterialProperties, uuid);
    }

    @Nonnull
    @Override
    public IRelatedCryptoMaterialComponentBuilder size(@Nullable INode size) {
        if (size == null) {
            return new RelatedCryptoMaterialComponentBuilder(
                    component, cryptoProperties, relatedCryptoMaterialProperties, uuid);
        }

        if (size instanceof SaltLength saltLength) {
            this.relatedCryptoMaterialProperties.setSize(saltLength.getValue());
        } else if (size instanceof PasswordLength passwordLength) {
            this.relatedCryptoMaterialProperties.setSize(passwordLength.getValue());
        } else if (size instanceof KeyLength keyLength) {
            this.relatedCryptoMaterialProperties.setSize(keyLength.getValue());
        } else if (size instanceof NonceLength nonceLength) {
            this.relatedCryptoMaterialProperties.setSize(nonceLength.getValue());
        } else if (size instanceof InitializationVectorLength initializationVectorLength) {
            this.relatedCryptoMaterialProperties.setSize(initializationVectorLength.getValue());
        }

        return new RelatedCryptoMaterialComponentBuilder(
                component, cryptoProperties, relatedCryptoMaterialProperties, uuid);
    }

    @Override
    public @Nonnull IRelatedCryptoMaterialComponentBuilder occurrences(
            @Nullable Occurrence... occurrences) {
        if (occurrences == null) {
            return new RelatedCryptoMaterialComponentBuilder(
                    component, cryptoProperties, relatedCryptoMaterialProperties, uuid);
        }
        final Evidence evidence = new Evidence();
        evidence.setOccurrences(List.of(occurrences));
        this.component.setEvidence(evidence);
        return new RelatedCryptoMaterialComponentBuilder(
                component, cryptoProperties, relatedCryptoMaterialProperties, uuid);
    }

    @Override
    public @Nonnull Component build() {
        this.cryptoProperties.setAssetType(AssetType.RELATED_CRYPTO_MATERIAL);
        this.cryptoProperties.setRelatedCryptoMaterialProperties(relatedCryptoMaterialProperties);

        this.component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        this.component.setCryptoProperties(this.cryptoProperties);
        this.component.setBomRef(this.uuid.toString());

        return this.component;
    }
}
