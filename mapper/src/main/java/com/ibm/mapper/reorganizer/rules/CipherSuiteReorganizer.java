package com.ibm.mapper.reorganizer.rules;

import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collections;

public final class CipherSuiteReorganizer {

    private CipherSuiteReorganizer() {
        // nothing
    }

    @Nonnull
    public static final IReorganizerRule ADD_TLS_PROTOCOL_AS_PARENT_NODE =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(CipherSuite.class)
                    .withDetectionCondition((node, parent, roots) -> parent == null)
                    .perform((node, parent, roots) -> {
                        if (node instanceof CipherSuite cipherSuite) {
                            final TLS tls = new TLS(cipherSuite.getDetectionContext());
                            tls.put(cipherSuite);
                            return new ArrayList<>(Collections.singleton(tls));
                        }
                        return roots;
                    });
}
