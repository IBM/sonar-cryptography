/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
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

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Maps the algorithm URIs of {@code System.Security.Cryptography.Xml} to mapper nodes.
 *
 * <p>Both the W3C URI and the {@code SignedXml} or {@code EncryptedXml} constant name are accepted.
 * The three methods read an identifier as a digest, a signature or an encryption algorithm; an
 * identifier of another kind gives nothing.
 *
 * <p>Not mapped: AES key wrap, RSA-PSS and GCM, which the model cannot carry.
 */
public final class DotNetXmlAlgorithmUris {

    private static final String DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final String DSIG_MORE = "http://www.w3.org/2001/04/xmldsig-more#";
    private static final String XMLENC = "http://www.w3.org/2001/04/xmlenc#";

    private DotNetXmlAlgorithmUris() {
        // utility
    }

    /** A digest identifier, as in {@code Reference.DigestMethod}. */
    @Nonnull
    public static Optional<INode> digest(@Nonnull String id, @Nonnull DetectionLocation location) {
        return switch (id.trim()) {
            case DSIG + "sha1", "XmlDsigSHA1Url" -> Optional.of(new SHA(location));
            case XMLENC + "sha256", "XmlDsigSHA256Url", "XmlEncSHA256Url" ->
                    Optional.of(new SHA2(256, location));
            case DSIG_MORE + "sha384", "XmlDsigSHA384Url" -> Optional.of(new SHA2(384, location));
            case XMLENC + "sha512", "XmlDsigSHA512Url", "XmlEncSHA512Url" ->
                    Optional.of(new SHA2(512, location));
            case DSIG_MORE + "md5" -> Optional.of(new MD5(location));
            case XMLENC + "ripemd160", "XmlDsigRIPEMD160Url" ->
                    Optional.of(new RIPEMD(160, location));
            default -> Optional.empty();
        };
    }

    /**
     * A signature identifier, as in {@code SignedInfo.SignatureMethod}. RSA, DSA and ECDSA give a
     * {@code Sign} with the digest (and PKCS#1 padding for RSA); an HMAC gives a MAC.
     */
    @Nonnull
    public static Optional<INode> signature(
            @Nonnull String id, @Nonnull DetectionLocation location) {
        return switch (id.trim()) {
            case DSIG + "rsa-sha1", "XmlDsigRSASHA1Url" -> rsa(new SHA(location), location);
            case DSIG_MORE + "rsa-sha256", "XmlDsigRSASHA256Url" ->
                    rsa(new SHA2(256, location), location);
            case DSIG_MORE + "rsa-sha384", "XmlDsigRSASHA384Url" ->
                    rsa(new SHA2(384, location), location);
            case DSIG_MORE + "rsa-sha512", "XmlDsigRSASHA512Url" ->
                    rsa(new SHA2(512, location), location);
            case DSIG + "dsa-sha1", "XmlDsigDSAUrl" -> signing(new SHA(location), location);
            case DSIG_MORE + "ecdsa-sha1" -> signing(new SHA(location), location);
            case DSIG_MORE + "ecdsa-sha256" -> signing(new SHA2(256, location), location);
            case DSIG_MORE + "ecdsa-sha384" -> signing(new SHA2(384, location), location);
            case DSIG_MORE + "ecdsa-sha512" -> signing(new SHA2(512, location), location);
            case DSIG + "hmac-sha1", "XmlDsigHMACSHA1Url" ->
                    Optional.of(new HMAC(new SHA(location)));
            case DSIG_MORE + "hmac-sha256" -> Optional.of(new HMAC(new SHA2(256, location)));
            case DSIG_MORE + "hmac-sha384" -> Optional.of(new HMAC(new SHA2(384, location)));
            case DSIG_MORE + "hmac-sha512" -> Optional.of(new HMAC(new SHA2(512, location)));
            default -> Optional.empty();
        };
    }

    /** An encryption identifier, as in {@code new EncryptionMethod(algorithm)}. */
    @Nonnull
    public static Optional<INode> encryption(
            @Nonnull String id, @Nonnull DetectionLocation location) {
        return switch (id.trim()) {
            case XMLENC + "aes128-cbc", "XmlEncAES128Url" ->
                    Optional.of(new AES(128, new CBC(location), location));
            case XMLENC + "aes192-cbc", "XmlEncAES192Url" ->
                    Optional.of(new AES(192, new CBC(location), location));
            case XMLENC + "aes256-cbc", "XmlEncAES256Url" ->
                    Optional.of(new AES(256, new CBC(location), location));
            // No key length is stated, so none is claimed.
            case XMLENC + "tripledes-cbc", "XmlEncTripleDESUrl" -> {
                final DESede node = new DESede(location);
                node.put(new CBC(location));
                yield Optional.of(node);
            }
            case XMLENC + "des-cbc", "XmlEncDESUrl" ->
                    Optional.of(new DES(new CBC(location), location));
            case XMLENC + "rsa-1_5", "XmlEncRSA15Url" -> {
                final RSA node = new RSA(location);
                node.put(new PKCS1(location));
                yield Optional.of(node);
            }
            // rsa-oaep-mgf1p is OAEP with SHA-1, fixed by the identifier
            case XMLENC + "rsa-oaep-mgf1p", "XmlEncRSAOAEPUrl" -> {
                final RSA node = new RSA(location);
                node.put(new OAEP(new SHA(location), location));
                yield Optional.of(node);
            }
            default -> Optional.empty();
        };
    }

    @Nonnull
    private static Optional<INode> rsa(
            @Nonnull MessageDigest digest, @Nonnull DetectionLocation location) {
        final Sign sign = new Sign(location);
        sign.put(digest);
        sign.put(new PKCS1(location));
        return Optional.of(sign);
    }

    @Nonnull
    private static Optional<INode> signing(
            @Nonnull MessageDigest digest, @Nonnull DetectionLocation location) {
        final Sign sign = new Sign(location);
        sign.put(digest);
        return Optional.of(sign);
    }
}
