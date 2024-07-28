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
package com.ibm.plugin.translation;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.HMAC;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class PythonTranslatorUtils {
    private PythonTranslatorUtils() {
        // private
    }

    @Nonnull
    public static PrivateKey generateEcPrivateKeyTranslation(
            @Nonnull String algorithmName,
            @Nonnull String curveName,
            @Nonnull DetectionLocation detectionLocation) {
        PrivateKey privateKey = new PrivateKey(algorithmName, detectionLocation);
        Algorithm baseAlgorithm = new Algorithm(algorithmName, detectionLocation);
        EllipticCurve ellipticCurve = new EllipticCurve(curveName, detectionLocation);
        EllipticCurveAlgorithm resAlgorithm =
                new EllipticCurveAlgorithm(baseAlgorithm, ellipticCurve);

        resAlgorithm.append(new KeyGeneration(detectionLocation));
        privateKey.append(resAlgorithm);

        PublicKey publicKey = new PublicKey(algorithmName, detectionLocation);
        publicKey.append(resAlgorithm.deepCopy());

        privateKey.append(publicKey);

        return privateKey;
    }

    @Nonnull
    public static PrivateKey generatePrivateKeyWithAlgorithm(
            @Nonnull String algorithmName,
            @Nonnull Optional<Integer> keyLength,
            @Nonnull DetectionLocation detectionLocation) {
        PrivateKey privateKey = new PrivateKey(algorithmName, detectionLocation);
        Algorithm baseAlgorithm = new Algorithm(algorithmName, detectionLocation);

        baseAlgorithm.append(new KeyGeneration(detectionLocation));
        privateKey.append(baseAlgorithm);
        if (keyLength.isPresent()) {
            privateKey.append(new KeyLength(keyLength.get(), detectionLocation));
            baseAlgorithm.append(new KeyLength(keyLength.get(), detectionLocation));
        }

        PublicKey publicKey = new PublicKey(algorithmName, detectionLocation);
        keyLength.ifPresent(integer -> publicKey.append(new KeyLength(integer, detectionLocation)));
        publicKey.append(baseAlgorithm.deepCopy());

        privateKey.append(publicKey);

        return privateKey;
    }

    @Nonnull
    public static PrivateKey generateOnlyPrivateKeyTranslation(
            @Nonnull String algorithmName, @Nonnull DetectionLocation detectionLocation) {
        PrivateKey privateKey = new PrivateKey(algorithmName, detectionLocation);
        Algorithm baseAlgorithm = new Algorithm(algorithmName, detectionLocation);
        baseAlgorithm.append(new KeyGeneration(detectionLocation));
        privateKey.append(baseAlgorithm);
        return privateKey;
    }

    @Nonnull
    public static PublicKey generateOnlyPublicKeyTranslation(
            @Nonnull String algorithmName, @Nonnull DetectionLocation detectionLocation) {
        PublicKey publicKey = new PublicKey(algorithmName, detectionLocation);
        Algorithm baseAlgorithm = new Algorithm(algorithmName, detectionLocation);
        baseAlgorithm.append(new KeyGeneration(detectionLocation));
        publicKey.append(baseAlgorithm);
        return publicKey;
    }

    @Nonnull
    public static StreamCipher generateNewStreamCipher(
            @Nonnull String cipherString,
            @Nonnull String macString,
            @Nonnull DetectionLocation detectionLocation) {
        StreamCipher cipher =
                new StreamCipher(new Algorithm(cipherString, detectionLocation), null, null);

        cipher.append(new HMAC(new Algorithm(macString, detectionLocation)));
        return cipher;
    }

    @Nonnull
    public static SecretKey generateSecretKeyWithAES(
            @Nonnull String algorithmFullName,
            @Nonnull Integer keyLength,
            @Nonnull DetectionLocation detectionLocation) {
        String modeString = "";
        switch (algorithmFullName) {
            case "AESGCM":
                modeString = "GCM";
                break;
            case "AESGCMSIV":
                modeString = "GCM";
                break;
            case "AESOCB3":
                modeString = "OCB";
                break;
            case "AESSIV":
                // TODO: Doing this creates an empty Mode node
                break;
            case "AESCCM":
                modeString = "CCM";
                break;
            default:
                return new SecretKey(algorithmFullName, detectionLocation);
        }

        String algorithmName = "AES";
        SecretKey secretKey = new SecretKey(algorithmName, detectionLocation);
        secretKey.append(new KeyLength(keyLength, detectionLocation));

        AuthenticatedEncryption cipher =
                new AuthenticatedEncryption(
                        new Algorithm(algorithmName, detectionLocation),
                        new Mode(modeString, detectionLocation),
                        null,
                        null);
        cipher.append(new KeyLength(keyLength, detectionLocation));
        cipher.append(new KeyGeneration(detectionLocation));
        secretKey.append(cipher);

        return secretKey;
    }
}
