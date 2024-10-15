package com.ibm.rules;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.functionality.Digest;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;

import java.util.List;

/**
 * While MD5 is still used in some applications, it is no longer considered secure for cryptographic
 * purposes like password hashing.
 * <br>
 * MD5 is cryptographically broken and should not be used for security-sensitive applications:
 * <ul>
 *  <li>It is vulnerable to collision attacks, where two different inputs can produce the same hash output</li>
 *  <li>It is computationally easy to generate MD5 hashes, making brute-force attacks feasible</li>
 * </ul>
 * MD5 can still be used for some non-cryptographic purposes like file integrity checking, to detect accidental corruption and
 * generating unique identifiers for caching or deduplication
 */
public final class NoMD5UseForMessageDigestRule<T> implements IReportableDetectionRule<T> {
    @Override
    public @NotNull List<Issue<T>> report(@NotNull T markerTree,
                                          @NotNull @Unmodifiable List<INode> translatedNodes) {
        return IssueCreator.using(markerTree, translatedNodes)
                .matchesCondition((node, parent) -> {
                    if (node instanceof MD5 md5) {
                        return md5.hasChildOfType(Digest.class).isPresent(); // only as tag is allowed
                    }
                    return false;
                })
                .create((markedTree, node, parent) -> new Issue<>(markedTree, "Do not use MD5"));
    }
}
