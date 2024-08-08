package com.ibm.enricher.algorithm;

import com.ibm.enricher.IEnricher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import org.jetbrains.annotations.NotNull;

public class RSAssaPSSEnricher implements IEnricher {
    @Override
    public @NotNull INode enrich(@NotNull INode node) {
        if (node instanceof RSAssaPSS rsaSsaPSS) {
            rsaSsaPSS.append(new Oid("1.2.840.113549.1.1.10", rsaSsaPSS.getDetectionContext()));
            return rsaSsaPSS;
        }
        return node;
    }
}
