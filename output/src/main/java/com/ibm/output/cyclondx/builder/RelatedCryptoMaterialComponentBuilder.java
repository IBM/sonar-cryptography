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
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.SaltLength;
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
import org.jetbrains.annotations.NotNull;

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

        if (name instanceof SaltLength) {
            this.component.setName("salt-" + this.uuid);
        } else if (name instanceof PasswordLength) {
            this.component.setName("password-" + this.uuid);
        }

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
        }

        return new RelatedCryptoMaterialComponentBuilder(
                component, cryptoProperties, relatedCryptoMaterialProperties, uuid);
    }

    @Override
    public @NotNull IRelatedCryptoMaterialComponentBuilder occurrences(
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
    public @NotNull Component build() {
        this.cryptoProperties.setAssetType(AssetType.RELATED_CRYPTO_MATERIAL);
        this.cryptoProperties.setRelatedCryptoMaterialProperties(relatedCryptoMaterialProperties);

        this.component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        this.component.setCryptoProperties(this.cryptoProperties);
        this.component.setBomRef(this.uuid.toString());

        return this.component;
    }
}
