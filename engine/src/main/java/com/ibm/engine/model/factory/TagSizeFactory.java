package com.ibm.engine.model.factory;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.TagSize;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Size;

import javax.annotation.Nonnull;
import java.util.Optional;

public class TagSizeFactory<T> extends SizeFactory<T> implements IValueFactory<T> {
    public TagSizeFactory() {
        super();
    }

    public TagSizeFactory(@Nonnull Size.UnitType interpretAsUnitType) {
        super(interpretAsUnitType);
    }

    @Nonnull
    @Override
    public Optional<IValue<T>> apply(@Nonnull ResolvedValue<Object, T> objectTResolvedValue) {
        return super.apply(
                objectTResolvedValue,
                (value, tree) -> new TagSize<>(value, Size.UnitType.BIT, tree));
    }
}
