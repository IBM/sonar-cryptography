package com.ibm.rules;

import com.ibm.mapper.model.INode;
import com.ibm.rules.builder.IFunctionMatchCondition;
import com.ibm.rules.builder.IFunctionReport;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.NoSuchElementException;

public final class IssueCreator<T> {
    @Nonnull
    @Unmodifiable
    private final List<INode> nodes;
    @Nonnull private final T markedTree;
    @Nullable private final INode matchedNode;
    @Nullable private final INode matchedParentNode;


    private IssueCreator(@Nonnull List<INode> nodes, @Nonnull T markedTree) {
        this.nodes = nodes;
        this.markedTree = markedTree;
        this.matchedNode = null;
        this.matchedParentNode = null;
    }

    private IssueCreator(@Nonnull List<INode> nodes,
                         @Nonnull T markedTree,
                         @Nullable INode matchedNode,
                         @Nullable INode matchedParentNode) {
        this.nodes = nodes;
        this.markedTree = markedTree;
        this.matchedNode = matchedNode;
        this.matchedParentNode = matchedParentNode;
    }

    @Nonnull
    public static <T> IssueCreator<T> using(@Nonnull T markedTree, @Nonnull @Unmodifiable List<INode> nodes) {
        return new IssueCreator<>(nodes, markedTree);
    }

    @Nonnull
    public IssueCreator<T> matchesCondition(@Nonnull IFunctionMatchCondition condition) {
        return matchesCondition(condition, this.nodes, null);
    }

    @Nonnull
    private IssueCreator<T> matchesCondition(@Nonnull IFunctionMatchCondition condition,
                                          @Nonnull List<INode> currentNodes,
                                          @Nullable INode parentNode) {
        for (final INode node : currentNodes) {
            final IssueCreator<T> t = matchesCondition(condition, node, parentNode);
            if (t.isMatched()) {
                return t;
            }

            if (!node.getChildren().isEmpty()) {
                final IssueCreator<T> s = matchesCondition(
                        condition, node.getChildren().values().stream().toList(),
                        node);
                if (t.isMatched()) {
                    return s;
                }
            }
        }
        return new IssueCreator<>(nodes, markedTree, null, null);
    }

    @Nonnull
    private IssueCreator<T> matchesCondition(@Nonnull IFunctionMatchCondition condition,
                                                   @Nonnull INode node,
                                                   @Nullable INode parentNode) {
        if (condition.apply(node, parentNode)) {
            return new IssueCreator<>(nodes, markedTree, node, matchedParentNode);
        }
        return new IssueCreator<>(nodes, markedTree, null, null);
    }


    private boolean isMatched() {
        return matchedNode != null;
    }

    @Nonnull
    public Issue<T> create(@Nonnull IFunctionReport<T> report) {
        if (this.matchedNode == null) {
            throw new NoSuchElementException("No matched node");
        }
        return report.apply(this.markedTree, this.matchedNode, this.matchedParentNode);
    }
}
