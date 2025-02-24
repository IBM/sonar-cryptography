package com.ibm.engine.model;

import javax.annotation.Nonnull;

public class TagSize<T> extends Size<T> {
    public TagSize(@Nonnull Integer value, @Nonnull UnitType unitType, @Nonnull T location) {
        super(value, unitType, location);
    }
}
