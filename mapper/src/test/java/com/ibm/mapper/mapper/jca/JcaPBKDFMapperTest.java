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
package com.ibm.mapper.mapper.jca;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.model.*;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaPBKDFMapperTest {

    @Test
    void base() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        JcaPBKDFMapper jcaPBKDFMapper = new JcaPBKDFMapper();
        Optional<PasswordBasedKeyDerivationFunction> pbkdfOptional =
                jcaPBKDFMapper.parse(
                        "PBKDF2WithHmacSHA256", testDetectionLocation, Configuration.DEFAULT);

        assertThat(pbkdfOptional).isPresent();
        assertThat(pbkdfOptional.get().getName()).isEqualTo("PBKDF2WithHmacSHA256");
        assertThat(pbkdfOptional.get().getIterations()).isEmpty();
        assertThat(pbkdfOptional.get().getSalt()).isEmpty();
        assertThat(pbkdfOptional.get().getDefaultKeyLength()).isEmpty();
        assertThat(pbkdfOptional.get().hasChildren()).isTrue();

        Map<Class<? extends INode>, INode> children = pbkdfOptional.get().getChildren();
        assertThat(children).hasSize(1);
        INode child = children.get(HMAC.class);
        assertThat(child.is(HMAC.class)).isTrue();

        HMAC mac = (HMAC) child;
        assertThat(mac.getName()).isEqualTo("HmacSHA256");
        assertThat(mac.hasChildren()).isTrue();
        children = mac.getChildren();
        assertThat(children).hasSize(2);
        child = children.get(MessageDigest.class);
        assertThat(child.is(MessageDigest.class)).isTrue();

        MessageDigest messageDigest = (MessageDigest) child;
        assertThat(messageDigest.getName()).isEqualTo("SHA256");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(256);
    }
}
