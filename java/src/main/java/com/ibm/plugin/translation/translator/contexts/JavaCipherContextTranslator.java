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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.BlockSize;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.mapper.mapper.bc.BcOperationModeEncryptionMapper;
import com.ibm.mapper.mapper.bc.BcOperationModeWrappingMapper;
import com.ibm.mapper.mapper.jca.JcaAlgorithmMapper;
import com.ibm.mapper.mapper.jca.JcaCipherOperationModeMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaCipherContextTranslator extends JavaAbstractLibraryTranslator {

    @Override
    @NotNull public Optional<INode> translateJCA(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree>) {
            JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
            return jcaAlgorithmMapper.parse(value.asString(), detectionLocation).map(a -> a);
        } else if (value instanceof OperationMode<Tree> operationMode) {
            JcaCipherOperationModeMapper jcaCipherOperationModeMapper =
                    new JcaCipherOperationModeMapper();
            return jcaCipherOperationModeMapper
                    .parse(operationMode.asString(), detectionLocation)
                    .map(f -> f);
        } else if (value instanceof CipherAction<Tree> cipherAction) {
            return switch (cipherAction.getAction()) {
                case WRAP -> Optional.of(new Encapsulate(detectionLocation));
                default -> Optional.empty();
            };
        }
        return Optional.empty();
    }

    @Override
    @NotNull public Optional<INode> translateBC(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        final CipherContext.Kind kind = ((CipherContext) detectionContext).kind();

        if (value instanceof OperationMode<Tree> operationMode) {
            return switch (kind) {
                case ENCRYPTION_STATUS -> {
                    BcOperationModeEncryptionMapper bcCipherOperationModeMapper =
                            new BcOperationModeEncryptionMapper();
                    yield bcCipherOperationModeMapper
                            .parse(operationMode.asString(), detectionLocation)
                            .map(f -> f);
                }
                case WRAPPING_STATUS -> {
                    BcOperationModeWrappingMapper bcOperationModeWrappingMapper =
                            new BcOperationModeWrappingMapper();
                    yield bcOperationModeWrappingMapper
                            .parse(operationMode.asString(), detectionLocation)
                            .map(f -> f);
                }
                default -> Optional.empty();
            };
        } else if (value instanceof ValueAction<Tree> valueAction) {
            //            com.ibm.mapper.model.Algorithm algorithm;
            //            BlockCipher blockCipher;
            //            AuthenticatedEncryption ae;
            //            PublicKeyEncryption pke;
            //            Mode mode;
            //            Padding padding;
            //            PasswordBasedEncryption pbe;

            switch (kind) {
                /*case ASYMMETRIC_CIPHER_ENGINE, BLOCK_CIPHER_ENGINE, WRAP_ENGINE:
                    return Optional.of(
                            new BlockCipher(
                                    new com.ibm.mapper.model.Algorithm(
                                            valueAction.asString(), detectionLocation)));
                case ASYMMETRIC_CIPHER_ENGINE_SIGNATURE:
                    return Optional.of(
                            new PublicKeyEncryption(
                                    new com.ibm.mapper.model.Algorithm(
                                            valueAction.asString(), detectionLocation)));
                case WRAP_RFC:
                    // Should the RFC value be reflected in the translation? Where?
                    return Optional.of(
                            new BlockCipher(
                                    new com.ibm.mapper.model.Algorithm(
                                            ITranslator.UNKNOWN, detectionLocation)));
                case STREAM_CIPHER_ENGINE:
                    return Optional.of(
                            new StreamCipher(
                                    new com.ibm.mapper.model.Algorithm(
                                            valueAction.asString(), detectionLocation)));
                case HASH:
                    return Optional.of(
                            new MessageDigest(
                                    new com.ibm.mapper.model.Algorithm(
                                            valueAction.asString(), detectionLocation)));
                case BLOCK_CIPHER, BUFFERED_BLOCK_CIPHER:
                    String blockCipherString = null;
                    String modeString = valueAction.asString();
                    boolean addMode = true;
                    String paddingString = "PKCS7";
                    boolean addPadding = false;

                    List<String> isNotAModeList =
                            List.of(
                                    "Buffered",
                                    "DefaultBuffered",
                                    "Padded",
                                    "PaddedBuffered",
                                    "PaddedBuffered(PKCS7)");
                    if (isNotAModeList.contains(modeString)) {
                        addMode = false;

                        if (modeString.contains(paddingString)) {
                            addPadding = true;
                        }
                    }

                    if (modeString.contains("|")) {
                        String[] split = modeString.split("\\|");
                        if (split.length != 2) {
                            break;
                        }

                        blockCipherString = split[0];
                        modeString = split[1];
                    }

                    mode = new Mode(modeString, detectionLocation);
                    padding = new Padding(paddingString, detectionLocation);
                    algorithm =
                            new com.ibm.mapper.model.Algorithm(
                                    blockCipherString != null
                                            ? blockCipherString
                                            : ITranslator.UNKNOWN,
                                    detectionLocation);
                    blockCipher =
                            new BlockCipher(
                                    algorithm, addMode ? mode : null, addPadding ? padding : null);
                    return Optional.of(blockCipher);
                case AEAD_BLOCK_CIPHER:
                    String modeName = valueAction.asString();

                    String defaultAlgorithmName = ITranslator.UNKNOWN;
                    // Some mode implementations assume a default BlockCipher
                    switch (modeName) {
                        case "GCM-SIV":
                            defaultAlgorithmName = "AES";
                            break;
                        case "KGCM":
                            defaultAlgorithmName = "DSTU7624:2014";
                            modeName = "GCM";
                            break;
                        default:
                            break;
                    }

                    mode = new Mode(modeName, detectionLocation);

                    algorithm =
                            new com.ibm.mapper.model.Algorithm(
                                    defaultAlgorithmName, detectionLocation);
                    final Cipher cipher = new Cipher(algorithm);
                    ae = new AuthenticatedEncryption(cipher, mode);
                    return Optional.of(ae);
                case AEAD_ENGINE:
                    ae =
                            new AuthenticatedEncryption(
                                    new com.ibm.mapper.model.Algorithm(
                                            valueAction.asString(), detectionLocation));
                    return Optional.of(ae);
                case CHACHA20POLY1305:
                    ae =
                            new AuthenticatedEncryption(
                                    new com.ibm.mapper.model.Algorithm(
                                            "ChaCha20Poly1305", detectionLocation),
                                    null,
                                    null,
                                    null);
                    HMAC mac =
                            new HMAC(
                                    new com.ibm.mapper.model.Algorithm(
                                            "Poly1305", detectionLocation));
                    mac.append(new Tag(detectionLocation));
                    mac.append(new Digest(detectionLocation));

                    ae.append(mac);
                    ae.append(
                            new StreamCipher(
                                    new com.ibm.mapper.model.Algorithm(
                                            "ChaCha20", detectionLocation)));
                    return Optional.of(ae);
                case ENCODING:
                    blockCipher =
                            new BlockCipher(
                                    new com.ibm.mapper.model.Algorithm(
                                            ITranslator.UNKNOWN, detectionLocation));

                    padding =
                            new Padding(valueAction.asString(), detectionLocation);
                    switch (valueAction.asString()) {
                        case "OAEP":
                            blockCipher.append(new OAEP(padding));
                            break;
                        default:
                            blockCipher.append(padding);
                            break;
                    }

                    return Optional.of(blockCipher);
                case ENCODING_SIGNATURE:
                    pke =
                            new PublicKeyEncryption(
                                    new com.ibm.mapper.model.Algorithm(
                                            ITranslator.UNKNOWN, detectionLocation));

                    padding =
                            new Padding(valueAction.asString(), detectionLocation);
                    switch (valueAction.asString()) {
                        case "OAEP":
                            pke.append(new OAEP(padding));
                            break;
                        default:
                            pke.append(padding);
                            break;
                    }

                    return Optional.of(pke);
                case ASYMMETRIC_BUFFERED_BLOCK_CIPHER:
                    blockCipher =
                            new BlockCipher(
                                    new com.ibm.mapper.model.Algorithm(
                                            ITranslator.UNKNOWN, detectionLocation));
                    return Optional.of(blockCipher);
                case PADDING:
                    padding =
                            new Padding(valueAction.asString(), detectionLocation);
                    return Optional.of(padding);
                case PBE:
                    String algorithmName = valueAction.asString();
                    switch (valueAction.asString()) {
                        case "OpenSSLPBE":
                            algorithmName = "PKCS #5 v2.0 Scheme 1";
                            break;
                        case "PKCS12":
                            algorithmName = "PKCS #12 v1.0";
                            break;
                        case "PKCS5S1":
                            algorithmName = "PKCS #5 v2.0 Scheme 1";
                            break;
                        case "PKCS5S2":
                            algorithmName = "PKCS #5 v2.0 Scheme 2";
                            break;
                        default:
                            break;
                    }

                    algorithm =
                            new com.ibm.mapper.model.Algorithm(algorithmName, detectionLocation);
                    pbe = new PasswordBasedEncryption(algorithm);

                    if (valueAction.asString().equals("OpenSSLPBE")) {
                        // Default digest is MD5
                        pbe.append(
                                new MessageDigest(
                                        new com.ibm.mapper.model.Algorithm(
                                                "MD5", detectionLocation)));
                    }

                    return Optional.of(pbe);*/
                default:
                    return Optional.empty(); // TODO
            }
        } else if (value instanceof AlgorithmParameter<Tree> algorithmParameter) {
            int keySize;
            switch (algorithmParameter.asString()) {
                case "ascon128", "SCHWAEMM128_128", "ascon128a", "SCHWAEMM256_128":
                    keySize = 128;
                    break;
                case "ascon128pq":
                    keySize = 160;
                    break;
                case "SCHWAEMM192_192":
                    keySize = 192;
                    break;
                case "SCHWAEMM256_256":
                    keySize = 256;
                    break;
                default:
                    return Optional.empty();
            }
            KeyLength keyLength = new KeyLength(keySize, detectionLocation);
            return Optional.of(keyLength);
        } else if (value instanceof BlockSize<Tree> blockSize) {
            return switch (kind) {
                case BLOCK_CIPHER, WRAP_ENGINE ->
                        Optional.of(
                                new com.ibm.mapper.model.BlockSize(
                                        Integer.parseInt(blockSize.asString()), detectionLocation));
                default -> Optional.empty();
            };
        }
        return Optional.empty();
    }
}
