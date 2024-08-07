package com.ibm.enricher.algorithm;

import com.ibm.mapper.model.IAsset;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface IEnrichWithDefaultKeySize {

    default void applyDefaultKeySize(@Nonnull IAsset asset, int defaultKeySize) {
        @Nullable INode keyLength = asset.hasChildOfType(KeyLength.class).orElse(null);
        // default key length
        if (keyLength == null) {
            switch (asset.getDetectionContext().bundle().getIdentifier()) {
                case "Jca":
                {
                    keyLength = new KeyLength(defaultKeySize, asset.getDetectionContext());
                    asset.append(keyLength);
                }
            }
        }
    }
}
