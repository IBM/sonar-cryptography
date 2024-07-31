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

import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.protocol.TLS;
import java.util.List;
import java.util.UUID;
import javax.annotation.Nonnull;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class ProtocolComponentBuilder implements IProtocolComponentBuilder {
    @Nonnull private final Component component;
    @Nonnull private final CryptoProperties cryptoProperties;
    @Nonnull private final ProtocolProperties protocolProperties;

    protected ProtocolComponentBuilder() {
        this.component = new Component();
        this.cryptoProperties = new CryptoProperties();
        this.protocolProperties = new ProtocolProperties();
    }

    private ProtocolComponentBuilder(
            @Nonnull Component component,
            @Nonnull CryptoProperties cryptoProperties,
            @Nonnull ProtocolProperties protocolProperties) {
        this.component = component;
        this.cryptoProperties = cryptoProperties;
        this.protocolProperties = protocolProperties;
    }

    @Nonnull
    public static IProtocolComponentBuilder create() {
        return new ProtocolComponentBuilder();
    }

    @NotNull @Override
    public IProtocolComponentBuilder name(@Nullable Protocol name) {
        if (name == null) {
            return new ProtocolComponentBuilder(component, cryptoProperties, protocolProperties);
        }

        this.component.setName(name.asString());
        return new ProtocolComponentBuilder(component, cryptoProperties, protocolProperties);
    }

    @NotNull @Override
    public IProtocolComponentBuilder type(@Nullable Protocol type) {
        if (type == null) {
            protocolProperties.setType(ProtocolType.UNKNOWN);
            return new ProtocolComponentBuilder(component, cryptoProperties, protocolProperties);
        }

        if (type instanceof TLS) {
            protocolProperties.setType(ProtocolType.TLS);
        } else {
            protocolProperties.setType(ProtocolType.OTHER);
        }

        return new ProtocolComponentBuilder(component, cryptoProperties, protocolProperties);
    }

    @NotNull @Override
    public IProtocolComponentBuilder version(@Nullable INode version) {
        if (version == null) {
            return new ProtocolComponentBuilder(component, cryptoProperties, protocolProperties);
        }
        protocolProperties.setVersion(version.asString());
        return new ProtocolComponentBuilder(component, cryptoProperties, protocolProperties);
    }

    @NotNull @Override
    public IProtocolComponentBuilder cipherSuites(@Nullable INode node) {
        if (node == null) {
            return new ProtocolComponentBuilder(component, cryptoProperties, protocolProperties);
        }

        if (node instanceof CipherSuiteCollection cipherSuiteCollection) {
            for (CipherSuite cipherSuite : cipherSuiteCollection.getCollection()) {
                final org.cyclonedx.model.component.crypto.CipherSuite suite =
                        new org.cyclonedx.model.component.crypto.CipherSuite();
                // name
                suite.setName(cipherSuite.getName());
                // algorithms
            }
        }

        return new ProtocolComponentBuilder(component, cryptoProperties, protocolProperties);
    }

    @NotNull @Override
    public IProtocolComponentBuilder occurrences(@Nullable Occurrence... occurrences) {
        if (occurrences == null) {
            return new ProtocolComponentBuilder(component, cryptoProperties, protocolProperties);
        }
        final Evidence evidence = new Evidence();
        evidence.setOccurrences(List.of(occurrences));
        this.component.setEvidence(evidence);
        return new ProtocolComponentBuilder(component, cryptoProperties, protocolProperties);
    }

    @NotNull @Override
    public Component build() {
        this.cryptoProperties.setAssetType(AssetType.PROTOCOL);
        this.cryptoProperties.setProtocolProperties(protocolProperties);

        this.component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        this.component.setCryptoProperties(this.cryptoProperties);
        this.component.setBomRef(UUID.randomUUID().toString());

        return this.component;
    }
}
