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
import com.ibm.mapper.model.functionality.*;
import com.ibm.mapper.model.padding.OAEP;
import java.util.*;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.jetbrains.annotations.NotNull;

public class AlgorithmComponentBuilder implements IAlgorithmComponentBuilder {
    @Nonnull private final Component component;
    @Nonnull private final CryptoProperties cryptoProperties;
    @Nonnull private final AlgorithmProperties algorithmProperties;

    @Nullable private INode algorithm;
    @Nullable private INode parameterSetIdentifier;
    @Nullable private INode mode;
    @Nullable private INode padding;
    @Nullable private INode curve;

    protected AlgorithmComponentBuilder() {
        this.component = new Component();
        this.cryptoProperties = new CryptoProperties();
        this.algorithmProperties = new AlgorithmProperties();
    }

    @SuppressWarnings("java:S107")
    public AlgorithmComponentBuilder(
            @Nonnull Component component,
            @Nonnull CryptoProperties cryptoProperties,
            @Nonnull AlgorithmProperties algorithmProperties,
            @Nullable INode algorithm,
            @Nullable INode parameterSetIdentifier,
            @Nullable INode mode,
            @Nullable INode padding,
            @Nullable INode curve) {
        this.component = component;
        this.cryptoProperties = cryptoProperties;
        this.algorithmProperties = algorithmProperties;
        this.algorithm = algorithm;
        this.parameterSetIdentifier = parameterSetIdentifier;
        this.mode = mode;
        this.padding = padding;
        this.curve = curve;
    }

    @Nonnull
    public static IAlgorithmComponentBuilder create() {
        return new AlgorithmComponentBuilder();
    }

    @Override
    public @NotNull IAlgorithmComponentBuilder algorithm(@Nullable INode algorithm) {
        this.algorithm = algorithm;
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @NotNull IAlgorithmComponentBuilder parameterSetIdentifier(
            @Nullable INode parameterSetIdentifier) {
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @NotNull IAlgorithmComponentBuilder mode(@Nullable INode mode) {
        if (mode == null) {
            return new AlgorithmComponentBuilder(
                    component,
                    cryptoProperties,
                    algorithmProperties,
                    algorithm,
                    parameterSetIdentifier,
                    this.mode,
                    padding,
                    curve);
        }
        this.mode = mode;
        Optional<org.cyclonedx.model.component.crypto.enums.Mode> m =
                Utils.parseStringToMode(mode.asString().toLowerCase());
        m.ifPresent(this.algorithmProperties::setMode);
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @NotNull IAlgorithmComponentBuilder primitive(@Nullable INode primitive) {
        if (primitive == null) {
            return new AlgorithmComponentBuilder(
                    component,
                    cryptoProperties,
                    algorithmProperties,
                    algorithm,
                    parameterSetIdentifier,
                    mode,
                    padding,
                    curve);
        }
        Primitive primitives;
        if (primitive.is(AuthenticatedEncryption.class)) {
            primitives = Primitive.AE;
        } else if (primitive.is(BlockCipher.class)) {
            primitives = Primitive.BLOCK_CIPHER;
        } else if (primitive.is(HMAC.class)) {
            primitives = Primitive.MAC;
        } else if (primitive.is(MessageDigest.class)) {
            primitives = Primitive.HASH;
        } else if (primitive.is(KeyDerivationFunction.class)
                || primitive.is(PasswordBasedKeyDerivationFunction.class)) {
            primitives = Primitive.KDF;
        } else if (primitive.is(PseudorandomNumberGenerator.class)) {
            primitives = Primitive.DRBG;
        } else if (primitive.is(Signature.class)) {
            primitives = Primitive.SIGNATURE;
        } else if (primitive.is(StreamCipher.class)) {
            primitives = Primitive.STREAM_CIPHER;
        } else if (primitive.is(PublicKeyEncryption.class)) {
            primitives = Primitive.PKE;
        } else if (primitive.is(KeyAgreement.class)) {
            primitives = Primitive.KEY_AGREE;
        } else if (primitive.is(KeyEncapsulationMechanism.class)) {
            primitives = Primitive.KEM;
        } else {
            primitives = Primitive.OTHER;
        }
        this.algorithmProperties.setPrimitive(primitives);
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @NotNull IAlgorithmComponentBuilder padding(@Nullable INode padding) {
        if (padding == null) {
            return new AlgorithmComponentBuilder(
                    component,
                    cryptoProperties,
                    algorithmProperties,
                    algorithm,
                    parameterSetIdentifier,
                    mode,
                    this.padding,
                    curve);
        }

        org.cyclonedx.model.component.crypto.enums.Padding p;
        if (padding.is(OAEP.class)) {
            p = org.cyclonedx.model.component.crypto.enums.Padding.OAEP;
        } else if (padding.is(Padding.class)) {
            final String paddingStr = padding.asString().toLowerCase();
            p =
                    switch (paddingStr) {
                        case "no" -> org.cyclonedx.model.component.crypto.enums.Padding.RAW;
                        case "pkcs1" -> org.cyclonedx.model.component.crypto.enums.Padding.PKCS1V15;
                        // ISO10126Padding
                        // PKCS5Padding
                        // SSL3Padding
                        case "pkcs5" -> org.cyclonedx.model.component.crypto.enums.Padding.PKCS5;
                        case "pkcs7" -> org.cyclonedx.model.component.crypto.enums.Padding.PKCS7;
                        default -> org.cyclonedx.model.component.crypto.enums.Padding.OTHER;
                    };
        } else {
            p = org.cyclonedx.model.component.crypto.enums.Padding.OTHER;
        }
        this.algorithmProperties.setPadding(p);
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @NotNull IAlgorithmComponentBuilder curve(@Nullable INode curve) {
        this.curve = curve;
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @NotNull IAlgorithmComponentBuilder cryptoFunctions(@Nullable INode... cryptoFunctions) {
        if (cryptoFunctions == null || cryptoFunctions.length == 0) {
            return new AlgorithmComponentBuilder(
                    component,
                    cryptoProperties,
                    algorithmProperties,
                    algorithm,
                    parameterSetIdentifier,
                    mode,
                    padding,
                    curve);
        }

        List<CryptoFunction> functions =
                Arrays.stream(cryptoFunctions)
                        .filter(Objects::nonNull)
                        .filter(Functionality.class::isInstance)
                        .map(
                                node -> {
                                    if (node.is(Tag.class)) {
                                        return CryptoFunction.TAG;
                                    } else if (node.is(Sign.class)) {
                                        return CryptoFunction.SIGN;
                                    } else if (node.is(Digest.class)) {
                                        return CryptoFunction.DIGEST;
                                    } else if (node.is(Verify.class)) {
                                        return CryptoFunction.VERIFY;
                                    } else if (node.is(Decrypt.class)) {
                                        return CryptoFunction.DECRYPT;
                                    } else if (node.is(Encrypt.class)) {
                                        return CryptoFunction.ENCRYPT;
                                    } else if (node.is(Generate.class)) {
                                        return CryptoFunction.GENERATE;
                                    } else if (node.is(Decapsulate.class)) {
                                        return CryptoFunction.DECAPSULATE;
                                    } else if (node.is(Encapsulate.class)) {
                                        return CryptoFunction.ENCAPSULATE;
                                    } else if (node.is(KeyDerivation.class)) {
                                        return CryptoFunction.KEYDERIVE;
                                    } else if (node.is(KeyGeneration.class)) {
                                        return CryptoFunction.KEYGEN;
                                    } else {
                                        return CryptoFunction.OTHER;
                                    }
                                })
                        .toList();

        this.algorithmProperties.setCryptoFunctions(functions);
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @NotNull IAlgorithmComponentBuilder occurrences(@Nullable Occurrence... occurrences) {
        if (occurrences == null) {
            return new AlgorithmComponentBuilder(
                    component,
                    cryptoProperties,
                    algorithmProperties,
                    algorithm,
                    parameterSetIdentifier,
                    mode,
                    padding,
                    curve);
        }

        final Evidence evidence = new Evidence();
        evidence.setOccurrences(List.of(occurrences));
        this.component.setEvidence(evidence);

        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @NotNull IAlgorithmComponentBuilder oid(@Nullable INode oid) {
        if (oid instanceof Oid oid1) {
            this.cryptoProperties.setOid(oid1.getValue());
        }
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @NotNull Component build() {
        AlgorithmVariant variant =
                new AlgorithmVariant(algorithm, parameterSetIdentifier, mode, padding, curve);
        if (parameterSetIdentifier != null) {
            this.algorithmProperties.setParameterSetIdentifier(parameterSetIdentifier.asString());
        }
        this.cryptoProperties.setAssetType(AssetType.ALGORITHM);
        this.cryptoProperties.setAlgorithmProperties(this.algorithmProperties);

        this.component.setCryptoProperties(this.cryptoProperties);
        this.component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        this.component.setBomRef(UUID.randomUUID().toString());
        this.component.setName(variant.toString());

        return this.component;
    }
}
