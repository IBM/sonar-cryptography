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

import com.ibm.mapper.model.*;
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

public class KeyComponentBuilder implements IKeyComponentBuilder {

    @Nonnull private final Component component;
    @Nonnull private final CryptoProperties cryptoProperties;
    @Nonnull private final RelatedCryptoMaterialProperties relatedCryptoMaterialProperties;

    @Nullable private INode keyAlgoName;
    @Nullable private INode keySize;

    protected KeyComponentBuilder() {
        this.component = new Component();
        this.cryptoProperties = new CryptoProperties();
        this.relatedCryptoMaterialProperties = new RelatedCryptoMaterialProperties();
    }

    public KeyComponentBuilder(
            @Nonnull Component component,
            @Nonnull CryptoProperties cryptoProperties,
            @Nonnull RelatedCryptoMaterialProperties relatedCryptoMaterialProperties,
            @Nullable INode keyAlgoName,
            @Nullable INode keySize) {
        this.component = component;
        this.cryptoProperties = cryptoProperties;
        this.relatedCryptoMaterialProperties = relatedCryptoMaterialProperties;
        this.keyAlgoName = keyAlgoName;
        this.keySize = keySize;
    }

    @Nonnull
    public static IKeyComponentBuilder create() {
        return new KeyComponentBuilder();
    }

    @Nonnull
    @Override
    public IKeyComponentBuilder name(@Nullable INode name) {
        if (name == null) {
            return new KeyComponentBuilder(
                    component,
                    cryptoProperties,
                    relatedCryptoMaterialProperties,
                    keyAlgoName,
                    keySize);
        }

        if (name instanceof Key key) {
            return new KeyComponentBuilder(
                    component, cryptoProperties, relatedCryptoMaterialProperties, key, keySize);
        }

        return new KeyComponentBuilder(
                component, cryptoProperties, relatedCryptoMaterialProperties, keyAlgoName, keySize);
    }

    @Nonnull
    @Override
    public IKeyComponentBuilder type(@Nullable INode type) {
        if (type == null) {
            return new KeyComponentBuilder(
                    component,
                    cryptoProperties,
                    relatedCryptoMaterialProperties,
                    keyAlgoName,
                    keySize);
        }

        RelatedCryptoMaterialType types = null;
        if (type.is(SecretKey.class)) {
            types = RelatedCryptoMaterialType.SECRET_KEY;
        } else if (type.is(PrivateKey.class)) {
            types = RelatedCryptoMaterialType.PRIVATE_KEY;
        } else if (type.is(PublicKey.class)) {
            types = RelatedCryptoMaterialType.PUBLIC_KEY;
        } else if (type.is(Key.class)) {
            types = RelatedCryptoMaterialType.SECRET_KEY;
        }

        if (types != null) {
            this.relatedCryptoMaterialProperties.setType(types);
        }

        return new KeyComponentBuilder(
                component, cryptoProperties, relatedCryptoMaterialProperties, keyAlgoName, keySize);
    }

    @Nonnull
    @Override
    public IKeyComponentBuilder size(@Nullable INode size) {
        if (size == null) {
            return new KeyComponentBuilder(
                    component,
                    cryptoProperties,
                    relatedCryptoMaterialProperties,
                    keyAlgoName,
                    keySize);
        }

        if (size.is(KeyLength.class)) {
            this.relatedCryptoMaterialProperties.setSize(((KeyLength) size).getValue());
            return new KeyComponentBuilder(
                    component,
                    cryptoProperties,
                    relatedCryptoMaterialProperties,
                    keyAlgoName,
                    size);
        }

        return new KeyComponentBuilder(
                component, cryptoProperties, relatedCryptoMaterialProperties, keyAlgoName, keySize);
    }

    @Override
    public @NotNull IKeyComponentBuilder occurrences(@Nullable Occurrence... occurrences) {
        if (occurrences == null) {
            return new KeyComponentBuilder(
                    component,
                    cryptoProperties,
                    relatedCryptoMaterialProperties,
                    keyAlgoName,
                    keySize);
        }
        final Evidence evidence = new Evidence();
        evidence.setOccurrences(List.of(occurrences));
        this.component.setEvidence(evidence);
        return new KeyComponentBuilder(
                component, cryptoProperties, relatedCryptoMaterialProperties, keyAlgoName, keySize);
    }

    @Override
    public @NotNull Component build() {
        AlgorithmVariant variant = new AlgorithmVariant(keyAlgoName, keySize, null, null, null);

        this.cryptoProperties.setAssetType(AssetType.RELATED_CRYPTO_MATERIAL);
        this.cryptoProperties.setRelatedCryptoMaterialProperties(relatedCryptoMaterialProperties);

        this.component.setCryptoProperties(this.cryptoProperties);
        this.component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        this.component.setBomRef(UUID.randomUUID().toString());
        this.component.setName("key:" + variant);

        return this.component;
    }
}
