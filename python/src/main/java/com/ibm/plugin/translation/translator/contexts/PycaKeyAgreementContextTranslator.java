package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.python.api.tree.Tree;

import java.util.Optional;

public class PycaKeyAgreementContextTranslator implements IContextTranslation<Tree> {
    @Override
    public @NotNull Optional<INode> translate(@NotNull IBundle bundleIdentifier,
                                              @NotNull IValue<Tree> value,
                                              @NotNull IDetectionContext detectionContext,
                                              @NotNull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree> algorithm) {
            return switch (algorithm.asString().toUpperCase().trim()) {
                case "EC" -> Optional.of(new EllipticCurveAlgorithm(KeyAgreement.class, new EllipticCurveAlgorithm(detectionLocation)));
                default -> Optional.empty();
            };
        }
        return Optional.empty();
    }
}
