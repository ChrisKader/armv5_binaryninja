/*
 * Dominator Tree Analysis
 *
 * Computes dominators and dominance frontiers for CFG analysis.
 * Used for loop detection and structured analysis.
 */

#pragma once

#include "control_flow_graph.h"

#include <vector>
#include <map>
#include <set>

namespace Armv5Analysis
{

/**
 * Information about a natural loop
 */
struct LoopInfo
{
	BasicBlock* header;                 // Loop header (dominator of back-edge target)
	std::set<BasicBlock*> body;         // All blocks in the loop
	std::set<BasicBlock*> backEdgeSources;  // Blocks with back-edges to header
	std::set<BasicBlock*> exitBlocks;   // Blocks that exit the loop
	int nestingLevel = 0;               // 0 = outermost loop

	bool contains(BasicBlock* block) const
	{
		return body.count(block) > 0;
	}
};

/**
 * Dominator tree for a control flow graph
 */
class DominatorTree
{
public:
	explicit DominatorTree(ControlFlowGraph& cfg);

	/**
	 * Compute the dominator tree using Lengauer-Tarjan algorithm
	 */
	void compute();

	/**
	 * Has the tree been computed?
	 */
	bool isComputed() const { return m_computed; }

	// =========================================================================
	// Dominator queries
	// =========================================================================

	/**
	 * Get the immediate dominator of a block
	 */
	BasicBlock* getImmediateDominator(BasicBlock* block);
	const BasicBlock* getImmediateDominator(const BasicBlock* block) const;

	/**
	 * Get all blocks immediately dominated by the given block
	 */
	std::vector<BasicBlock*> getDominatees(BasicBlock* block);

	/**
	 * Does 'dominator' dominate 'dominated'?
	 */
	bool dominates(BasicBlock* dominator, BasicBlock* dominated) const;

	/**
	 * Does 'dominator' strictly dominate 'dominated'?
	 * (dominates but is not equal)
	 */
	bool strictlyDominates(BasicBlock* dominator, BasicBlock* dominated) const;

	/**
	 * Get the depth in the dominator tree (0 = entry)
	 */
	int getDominatorDepth(BasicBlock* block) const;

	// =========================================================================
	// Loop detection
	// =========================================================================

	/**
	 * Find all natural loops in the CFG
	 */
	std::vector<LoopInfo> findNaturalLoops();

	/**
	 * Is this block a loop header?
	 */
	bool isLoopHeader(BasicBlock* block) const;

	/**
	 * Get the innermost loop containing a block
	 */
	const LoopInfo* getLoopFor(BasicBlock* block) const;

	/**
	 * Get the loop nesting depth for a block (0 = not in loop)
	 */
	int getLoopDepth(BasicBlock* block) const;

private:
	// =========================================================================
	// Lengauer-Tarjan algorithm data structures
	// =========================================================================

	void dfs(BasicBlock* block);
	BasicBlock* eval(BasicBlock* v);
	void link(BasicBlock* v, BasicBlock* w);
	void computeSemiDominators();
	void computeImmediateDominators();

	/**
	 * Find the natural loop body for a back-edge
	 */
	std::set<BasicBlock*> findLoopBody(BasicBlock* header, BasicBlock* backEdgeSource);

	ControlFlowGraph& m_cfg;
	bool m_computed = false;

	// Dominator tree structure
	std::map<BasicBlock*, BasicBlock*> m_idom;  // Immediate dominator
	std::map<BasicBlock*, std::vector<BasicBlock*>> m_children;  // Dominator tree children
	std::map<BasicBlock*, int> m_depth;  // Depth in dominator tree

	// Lengauer-Tarjan algorithm state
	std::map<BasicBlock*, int> m_dfnum;          // DFS number
	std::vector<BasicBlock*> m_vertex;           // DFS order
	std::map<BasicBlock*, BasicBlock*> m_parent; // DFS parent
	std::map<BasicBlock*, BasicBlock*> m_semi;   // Semi-dominator
	std::map<BasicBlock*, BasicBlock*> m_ancestor;
	std::map<BasicBlock*, BasicBlock*> m_best;
	std::map<BasicBlock*, std::vector<BasicBlock*>> m_bucket;

	// Cached loop information
	std::vector<LoopInfo> m_loops;
	std::map<BasicBlock*, const LoopInfo*> m_blockToLoop;
	bool m_loopsComputed = false;
};

}  // namespace Armv5Analysis
