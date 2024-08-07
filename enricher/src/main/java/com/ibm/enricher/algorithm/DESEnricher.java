package com.ibm.enricher.algorithm;

import com.ibm.enricher.IEnricher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.DES;
import org.jetbrains.annotations.NotNull;

public class DESEnricher implements IEnricher, IEnrichWithDefaultKeySize {
    @Override
    public @NotNull INode enrich(@NotNull INode node) {
        if (node instanceof DES des) {
            this.applyDefaultKeySize(des, 56);
            return des;
        }
        return node;
    }
}
