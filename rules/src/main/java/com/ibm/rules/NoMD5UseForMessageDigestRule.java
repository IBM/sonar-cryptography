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
package com.ibm.rules;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.rules.issue.Issue;
import com.ibm.rules.issue.IssueCreator;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * While MD5 is still used in some applications, it is no longer considered secure for cryptographic
 * purposes like password hashing. <br>
 * MD5 is cryptographically broken and should not be used for security-sensitive applications:
 *
 * <ul>
 *   <li>It is vulnerable to collision attacks, where two different inputs can produce the same hash
 *       output
 *   <li>It is computationally easy to generate MD5 hashes, making brute-force attacks feasible
 * </ul>
 *
 * MD5 can still be used for some non-cryptographic purposes like file integrity checking, to detect
 * accidental corruption and generating unique identifiers for caching or deduplication
 */
public final class NoMD5UseForMessageDigestRule<T> implements IReportableDetectionRule<T> {
    @Override
    public @Nonnull List<Issue<T>> report(
            @Nonnull T markerTree, @Nonnull List<INode> translatedNodes) {
        return IssueCreator.using(markerTree, translatedNodes)
                .matchesCondition(
                        (node, parent) -> {
                            if (node instanceof MD5 md5) {
                                return md5.hasChildOfType(Digest.class)
                                        .isPresent(); // only as tag is allowed
                            }
                            return false;
                        })
                .create(
                        (markedTree, node, parent) ->
                                new Issue<>(
                                        markedTree,
                                        "Do not use MD5 for cryptographic purposes like hashing"));
    }
}
