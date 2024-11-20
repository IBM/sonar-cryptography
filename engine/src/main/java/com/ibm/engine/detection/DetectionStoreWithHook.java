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
package com.ibm.engine.detection;

import com.ibm.engine.executive.IStatusReporting;
import com.ibm.engine.hooks.*;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.IDetectionRule;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class DetectionStoreWithHook<R, T, S, P> extends DetectionStore<R, T, S, P> {
    @Nonnull private final DetectionStoreWithHook<R, T, S, P> hookRootDetectionStore;
    @Nonnull private final T invocationTree;

    public DetectionStoreWithHook(
            final int level,
            @Nonnull final IDetectionRule<T> detectionRule,
            @Nonnull final IScanContext<R, T> scanContext,
            @Nonnull final Handler<R, T, S, P> handler,
            @Nonnull final IStatusReporting<R, T, S, P> statusReporting,
            @Nonnull final T invocationTree) {
        super(level, detectionRule, scanContext, handler, statusReporting);
        this.invocationTree = invocationTree;
        this.hookRootDetectionStore = this;
    }

    public DetectionStoreWithHook(
            final int level,
            @Nonnull final IDetectionRule<T> detectionRule,
            @Nonnull final T invocationTree,
            @Nonnull final DetectionStoreWithHook<R, T, S, P> hookRootDetectionStore) {
        super(
                level,
                detectionRule,
                hookRootDetectionStore.scanContext,
                hookRootDetectionStore.handler,
                hookRootDetectionStore.statusReporting);
        this.invocationTree = invocationTree;
        this.hookRootDetectionStore = hookRootDetectionStore;
    }

    public void onHookInvocation(
            @Nonnull final T invocationTree, @Nonnull final IHook<R, T, S, P> hook) {
        onHookInvocation(invocationTree, hook, false);
    }

    public void onSuccessiveHook(@Nonnull final IHook<R, T, S, P> hook) {
        if (!hook.isInvocationOn(invocationTree, handler.getLanguageSupport())) {
            // Add a hook to the hook repository
            if (handler.addHookToHookRepository(hook)) {
                /*
                 * Subscribes to the hook detection observable for the given hook value and attaches the new
                 * Detection Store to it, so that it can receive detection events.
                 */
                handler.subscribeToHookDetectionObservable(hook, hookRootDetectionStore);
            }
        } else {
            onHookInvocation(invocationTree, hook, true);
        }
    }

    private void onHookInvocation(
            @Nonnull final T invocationTree,
            @Nonnull final IHook<R, T, S, P> hook,
            boolean isSuccessive) {
        if (hook
                instanceof
                MethodInvocationHookWithParameterResolvement<R, T, S, P>
                        methodInvocationHookWithParameterResolvement) {
            handleMethodInvocationHookWithParameterResolvement(
                    invocationTree, methodInvocationHookWithParameterResolvement, isSuccessive);
        } else if (hook
                instanceof
                MethodInvocationHookWithReturnResolvement<R, T, S, P>
                        methodInvocationHookWithReturnResolvement) {
            handleMethodInvocationHookWithReturnResolvement(
                    methodInvocationHookWithReturnResolvement, isSuccessive);
        } else if (hook instanceof EnumHook<R, T, S, P> enumHook) {
            handleEnumHook(invocationTree, enumHook);
        }
    }

    @Override
    public boolean isRootHook() {
        return false;
    }

    private void handleMethodInvocationHookWithReturnResolvement(
            @Nonnull
                    final MethodInvocationHookWithReturnResolvement<R, T, S, P>
                            methodInvocationHookWithReturnResolvement,
            boolean isSuccessive) {
        final IDetectionEngine<T, S> detectionEngine =
                handler.getLanguageSupport().createDetectionEngineInstance(hookRootDetectionStore);
        detectionEngine.resolveMethodReturnValues(
                Object.class,
                methodInvocationHookWithReturnResolvement.methodDefinition(),
                methodInvocationHookWithReturnResolvement.getParameter());
        handleNextRulesForMethodHooks(
                methodInvocationHookWithReturnResolvement, null, isSuccessive);
    }

    private void handleMethodInvocationHookWithParameterResolvement(
            @Nonnull final T methodInvocation,
            @Nonnull
                    final MethodInvocationHookWithParameterResolvement<R, T, S, P>
                            methodInvocationHookWithParameterResolvement,
            boolean isSuccessive) {
        final IDetectionEngine<T, S> detectionEngine =
                handler.getLanguageSupport().createDetectionEngineInstance(hookRootDetectionStore);
        final T argument =
                detectionEngine.extractArgumentFromMethodCaller(
                        methodInvocationHookWithParameterResolvement.methodDefinition(),
                        methodInvocation,
                        methodInvocationHookWithParameterResolvement.methodParameter());
        if (argument == null) {
            return;
        }

        List<ResolvedValue<Object, T>> resolvedValues;
        if (methodInvocationHookWithParameterResolvement.getParameter()
                instanceof DetectableParameter<T> detectableParameter) {
            resolvedValues =
                    detectionEngine.resolveValuesInInnerScope(
                            Object.class, argument, detectableParameter.getiValueFactory());
        } else {
            resolvedValues =
                    detectionEngine.resolveValuesInInnerScope(Object.class, argument, null);
        }
        if (resolvedValues.isEmpty()) {
            detectionEngine.resolveValuesInOuterScope(
                    argument, methodInvocationHookWithParameterResolvement.getParameter());
            return;
        }

        if (methodInvocationHookWithParameterResolvement.getParameter()
                instanceof DetectableParameter<T> detectableParameter) {
            resolvedValues.stream()
                    .map(
                            resolvedValue ->
                                    new ValueDetection<>(
                                            resolvedValue, detectableParameter, argument, null))
                    .map(detection -> detection.toValue(detectableParameter.getiValueFactory()))
                    .forEach(
                            iValue ->
                                    iValue.ifPresent(
                                            iValue1 ->
                                                    addValue(
                                                            detectableParameter.getIndex(),
                                                            iValue1)));
        }

        final TraceSymbol<S> traceSymbolForParameter =
                getParameterTraceSymbol(
                        methodInvocationHookWithParameterResolvement.methodParameter(),
                        methodInvocationHookWithParameterResolvement.getParameter());
        handleNextRulesForMethodHooks(
                methodInvocationHookWithParameterResolvement,
                traceSymbolForParameter,
                isSuccessive);
    }

    private void handleNextRulesForMethodHooks(
            @Nonnull final IMethodInvocationHook<R, T, S, P> hook,
            @Nullable final TraceSymbol<S> traceSymbolForParameter,
            boolean isSuccessive) {
        final TraceSymbol<S> traceSymbol =
                Objects.requireNonNullElseGet(traceSymbolForParameter, TraceSymbol::createStart);

        hook.getParameter().getDetectionRules().stream()
                .map(
                        iDetectionRule ->
                                new DetectionStoreWithHook<>(
                                        level + 1,
                                        iDetectionRule,
                                        invocationTree,
                                        hookRootDetectionStore))
                .forEach(
                        newDetectionStore -> {
                            attach(hook.getParameter().getIndex(), newDetectionStore);
                            handler.getLanguageSupport()
                                    .getBaseMethodVisitorFactory()
                                    .create(
                                            traceSymbol,
                                            handler.getLanguageSupport()
                                                    .createDetectionEngineInstance(
                                                            newDetectionStore))
                                    .visitMethodDefinition(hook.methodDefinition());
                        });

        // add additional expected rule visits based on the size of the next detection rules
        statusReporting.addAdditionalExpectedRuleVisits(detectionRule.nextDetectionRules().size());

        detectionRule.nextDetectionRules().stream()
                .map(
                        iDetectionRule ->
                                new DetectionStoreWithHook<>(
                                        level + 1,
                                        iDetectionRule,
                                        invocationTree,
                                        hookRootDetectionStore))
                .forEach(
                        newDetectionStore -> {
                            attach(newDetectionStore);
                            statusReporting.incrementVisitedRules();
                            handler.getLanguageSupport()
                                    .getBaseMethodVisitorFactory()
                                    .create(
                                            TraceSymbol.createStart(),
                                            handler.getLanguageSupport()
                                                    .createDetectionEngineInstance(
                                                            newDetectionStore))
                                    .visitMethodDefinition(hook.methodDefinition());
                        });

        // emit a finding to the status report if the root detection store contains any findings
        if (!isSuccessive) {
            statusReporting.emitFinding(hookRootDetectionStore);
        }
    }

    private void handleEnumHook(
            @Nonnull final T enumClassDefinition, @Nonnull final EnumHook<R, T, S, P> enumHook) {
        final IDetectionEngine<T, S> detectionEngine =
                handler.getLanguageSupport().createDetectionEngineInstance(hookRootDetectionStore);
        final ResolvedValue<Object, T> resolvedEnumValue =
                detectionEngine.resolveEnumValue(
                        Object.class, enumClassDefinition, enumHook.selections());
        if (resolvedEnumValue == null) {
            return;
        }

        if (enumHook.parameter().is(DetectableParameter.class)) {
            final DetectableParameter<T> detectableParameter =
                    (DetectableParameter<T>) enumHook.parameter();
            new ValueDetection<>(
                            resolvedEnumValue,
                            detectableParameter,
                            enumHook.hookValue(),
                            resolvedEnumValue.tree())
                    .toValue(detectableParameter.getiValueFactory())
                    .ifPresent(iValue -> addValue(detectableParameter.getIndex(), iValue));
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DetectionStoreWithHook<?, ?, ?, ?> that)) return false;
        return Objects.equals(
                        this.hookRootDetectionStore.detectionRule,
                        that.hookRootDetectionStore.detectionRule)
                && Objects.equals(
                        this.hookRootDetectionStore.detectionValues,
                        that.hookRootDetectionStore.detectionValues)
                && Objects.equals(
                        this.hookRootDetectionStore.actionValue,
                        that.hookRootDetectionStore.actionValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                this.hookRootDetectionStore.detectionRule,
                this.hookRootDetectionStore.detectionValues,
                this.hookRootDetectionStore.actionValue);
    }
}
