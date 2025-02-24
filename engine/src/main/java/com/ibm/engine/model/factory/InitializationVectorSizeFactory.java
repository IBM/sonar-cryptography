package com.ibm.engine.model.factory;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.InitializationVectorSize;
import com.ibm.engine.model.Size;

import javax.annotation.Nonnull;
import java.util.Optional;

public class InitializationVectorSizeFactory <T> extends SizeFactory<T> implements IValueFactory<T> {

    public InitializationVectorSizeFactory() {
        super();
    }

    public InitializationVectorSizeFactory(@Nonnull Size.UnitType interpretAsUnitType) {
        super(interpretAsUnitType);
    }

    @Nonnull
    @Override
    public Optional<IValue<T>> apply(@Nonnull ResolvedValue<Object, T> objectTResolvedValue) {
        return super.apply(
                objectTResolvedValue,
                (value, tree) -> new InitializationVectorSize<>(value, Size.UnitType.BIT, tree));
    }
}