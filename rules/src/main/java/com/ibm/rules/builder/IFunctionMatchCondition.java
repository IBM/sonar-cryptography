package com.ibm.rules.builder;

import com.ibm.mapper.model.INode;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.function.BiFunction;

public interface IFunctionMatchCondition extends BiFunction<INode, INode, Boolean> {

    @Override
    @Nonnull
    Boolean apply(@Nonnull INode node, @Nullable INode parent);
}
