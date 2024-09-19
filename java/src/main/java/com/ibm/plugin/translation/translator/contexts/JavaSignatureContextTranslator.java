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

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.mapper.mapper.bc.BcDsaMapper;
import com.ibm.mapper.mapper.bc.BcMessageSignerMapper;
import com.ibm.mapper.mapper.bc.BcOperationModeSigningMapper;
import com.ibm.mapper.mapper.bc.BcSignatureMapper;
import com.ibm.mapper.mapper.jca.JcaAlgorithmMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaSignatureContextTranslator extends JavaAbstractLibraryTranslator {

    @Override
    protected @NotNull Optional<INode> translateJCA(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree>) {
            final JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
            return jcaAlgorithmMapper.parse(value.asString(), detectionLocation).map(a -> a);
        } else if (value instanceof SignatureAction<Tree> signatureAction) {
            return switch (signatureAction.getAction()) {
                case SIGN -> Optional.of(new Sign(detectionLocation));
                case VERIFY -> Optional.of(new Verify(detectionLocation));
            };
        } else if (value instanceof SaltSize<Tree> saltSize) {
            return Optional.of(new SaltLength(saltSize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }

    @Override
    protected @NotNull Optional<INode> translateBC(
            @NotNull IValue<Tree> value,
            @NotNull IDetectionContext detectionContext,
            @NotNull DetectionLocation detectionLocation) {
        if (value instanceof ValueAction<Tree> valueAction
                && detectionContext instanceof DetectionContext context) {
            String kind = context.get("kind").map(k -> k).orElse("");
            switch (kind) {
                case "DSA":
                    BcDsaMapper bcDSAMapper = new BcDsaMapper();
                    return bcDSAMapper.parse(valueAction.asString(), detectionLocation).map(f -> f);
                case "MESSAGE_SIGNER":
                    BcMessageSignerMapper bcMessageSignerMapper = new BcMessageSignerMapper();
                    return bcMessageSignerMapper
                            .parse(valueAction.asString(), detectionLocation)
                            .map(f -> f);
                default:
                    BcSignatureMapper bcSignatureMapper = new BcSignatureMapper();
                    return bcSignatureMapper
                            .parse(valueAction.asString(), detectionLocation)
                            .map(f -> f);
            }
        } else if (value instanceof OperationMode<Tree> operationMode) {
            BcOperationModeSigningMapper bcOperationModeSigningMapper =
                    new BcOperationModeSigningMapper();
            return bcOperationModeSigningMapper
                    .parse(operationMode.asString(), detectionLocation)
                    .map(f -> f);
        } else if (value instanceof SaltSize<Tree> saltSize) {
            return Optional.of(new SaltLength(saltSize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }
}
