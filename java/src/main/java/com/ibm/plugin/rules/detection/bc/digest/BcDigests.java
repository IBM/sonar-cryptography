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
package com.ibm.plugin.rules.detection.bc.digest;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.DigestSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcDigests {

    private BcDigests() {
        // nothing
    }

    private static BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        /* Digests with non-standard type */
        infoMap.putKey("KangarooTwelve")
                // The $ indicates a nested class
                .putType("org.bouncycastle.crypto.digests.Kangaroo$");
        infoMap.putKey("MarsupilamiFourteen")
                // The $ indicates a nested class
                .putType("org.bouncycastle.crypto.digests.Kangaroo$");
        infoMap.putKey("KMAC").putType("org.bouncycastle.crypto.macs.");
        infoMap.putKey("LMSContext").putType("org.bouncycastle.pqc.crypto.lms.");

        /*
         * Digests with standard type (in `org.bouncycastle.crypto.digests`):
         * Because several digests below are parent classes of others, but are still public classes with
         * a constructor, we use `forObjectExactTypes` in associated rules otherwise we would have several
         * detections (a class and its parent) instead of one.
         */
        infoMap.putKey("AsconDigest").putName("Ascon");
        infoMap.putKey("AsconXof").putName("Ascon-Xof");
        infoMap.putKey("Blake2bDigest").putName("BLAKE2b");
        infoMap.putKey("Blake2bpDigest").putName("BLAKE2bp");
        infoMap.putKey("Blake2sDigest").putName("BLAKE2s");
        infoMap.putKey("Blake2spDigest").putName("BLAKE2sp");
        infoMap.putKey("Blake2xsDigest").putName("BLAKE2xs");
        infoMap.putKey("Blake3Digest").putName("BLAKE3");
        infoMap.putKey("CSHAKEDigest").putName("cSHAKE");
        infoMap.putKey("DSTU7564Digest").putName("DSTU 7564");
        infoMap.putKey("GOST3411_2012_256Digest"); // Contains size -> handled in translation
        infoMap.putKey("GOST3411_2012_512Digest"); // Contains size -> handled in translation
        infoMap.putKey("GOST3411Digest").putName("GOST R 34.11");
        infoMap.putKey("Haraka256Digest"); // Contains size -> handled in translation
        infoMap.putKey("Haraka512Digest"); // Contains size -> handled in translation
        infoMap.putKey("HarakaBase").putName("Haraka"); // Parent class
        infoMap.putKey("ISAPDigest").putName("ISAP");
        infoMap.putKey("KeccakDigest").putName("Keccak"); // Parent class
        infoMap.putKey("MD2Digest").putName("MD2");
        infoMap.putKey("MD4Digest").putName("MD4");
        infoMap.putKey("MD5Digest").putName("MD5");
        infoMap.putKey("NullDigest").putName("Null");
        infoMap.putKey("ParallelHash").putName("ParallelHash");
        infoMap.putKey("PhotonBeetleDigest").putName("PHOTON-Beetle");
        infoMap.putKey("RIPEMD128Digest"); // Contains size -> handled in translation
        infoMap.putKey("RIPEMD160Digest"); // Contains size -> handled in translation
        infoMap.putKey("RIPEMD256Digest"); // Contains size -> handled in translation
        infoMap.putKey("RIPEMD320Digest"); // Contains size -> handled in translation
        infoMap.putKey("SHA1Digest").putName("SHA-1");
        infoMap.putKey("SHA224Digest").putName("SHA-224");
        infoMap.putKey("SHA256Digest").putName("SHA-256");
        infoMap.putKey("SHA384Digest").putName("SHA-384");
        infoMap.putKey("SHA3Digest").putName("SHA-3");
        infoMap.putKey("SHA512Digest").putName("SHA-512");
        infoMap.putKey("SHA512tDigest").putName("SHA-512/t");
        infoMap.putKey("SHAKEDigest").putName("SHAKE"); // Parent class
        infoMap.putKey("SkeinDigest").putName("Skein");
        infoMap.putKey("SM3Digest").putName("SM3");
        infoMap.putKey("SparkleDigest").putName("Sparkle");
        infoMap.putKey("TigerDigest").putName("Tiger");
        infoMap.putKey("TupleHash").putName("TupleHash");
        infoMap.putKey("WhirlpoolDigest").putName("Whirlpool");
        infoMap.putKey("XoodyakDigest").putName("Xoodyak");
    }

    private static final List<IDetectionRule<Tree>> regularConstructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null ? detectionValueContext : new DigestContext();

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String digest = entry.getKey();
            String digestName = infoMap.getDisplayName(digest, "Digest");
            String digestTypePrefix =
                    entry.getValue().getType() != null
                            ? entry.getValue().getType()
                            : "org.bouncycastle.crypto.digests.";
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectExactTypes(digestTypePrefix + digest)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(digestName))
                            // We want to capture all possible constructors (some have arguments)
                            .withAnyParameters()
                            .buildForContext(context)
                            .inBundle(() -> "Bc")
                            .withoutDependingDetectionRules());
        }

        return constructorsList;
    }

    private static final List<IDetectionRule<Tree>> otherConstructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null ? detectionValueContext : new DigestContext();

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes("org.bouncycastle.crypto.digests.NonMemoableDigest")
                        .forConstructor()
                        // .shouldBeDetectedAs(new ValueActionFactory<>("NonMemoable"))
                        .withMethodParameter("org.bouncycastle.crypto.Digest")
                        .addDependingDetectionRules(regularConstructors(detectionValueContext))
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes("org.bouncycastle.crypto.digests.ShortenedDigest")
                        .forConstructor()
                        // .shouldBeDetectedAs(new ValueActionFactory<>("Shortened"))
                        .withMethodParameter("org.bouncycastle.crypto.Digest")
                        .addDependingDetectionRules(regularConstructors(detectionValueContext))
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new DigestSizeFactory<>(Size.UnitType.BYTE))
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        return constructorsList;
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return rules(null);
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return Stream.concat(
                        regularConstructors(detectionValueContext).stream(),
                        otherConstructors(detectionValueContext).stream())
                .toList();
    }
}
