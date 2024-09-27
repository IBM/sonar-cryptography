package com.ibm.rules;

import javax.annotation.Nonnull;

public record Issue<T>(@Nonnull T tree, @Nonnull String message) {
}
