package com.ibm.engine.model;

import javax.annotation.Nonnull;

public class InitializationVectorSize<T> extends Size<T> {
    public InitializationVectorSize(@Nonnull Integer value, @Nonnull UnitType unitType, @Nonnull T location) {
        super(value, unitType, location);
    }
}
