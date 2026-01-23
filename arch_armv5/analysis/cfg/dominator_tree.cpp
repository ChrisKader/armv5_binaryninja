/*
 * Dominator Tree - Implementation
 *
 * Uses the Lengauer-Tarjan algorithm for efficient dominator computation.
 */

#include "dominator_tree.h"

#include <algorithm>
#include <stack>

namespace Armv5Analysis
{

DominatorTree::DominatorTree(ControlFlowGraph& cfg)
	: m_cfg(cfg)
{
}

void DominatorTree::compute()
{
	if (!m_cfg.isValid())
		return;

	// Clear previous computation
	m_idom.clear();
	m_children.clear();
	m_depth.clear();
	m_dfnum.clear();
	m_vertex.clear();
	m_parent.clear();
	m_semi.clear();
	m_ancestor.clear();
	m_best.clear();
	m_bucket.clear();

	// Step 1: DFS numbering
	BasicBlock* entry = m_cfg.getEntryBlock();
	if (!entry)
		return;

	dfs(entry);

	// Initialize semi, ancestor, and best
	for (BasicBlock* block : m_vertex)
	{
		m_semi[block] = block;
		m_ancestor[block] = nullptr;
		m_best[block] = block;
	}

	// Steps 2 & 3: Compute semi-dominators and implicit idoms
	computeSemiDominators();

	// Step 4: Compute immediate dominators
	computeImmediateDominators();

	// Build dominator tree children and depths
	for (auto& kv : m_idom)
	{
		BasicBlock* block = kv.first;
		BasicBlock* idom = kv.second;
		if (idom)
			m_children[idom].push_back(block);
	}

	// Compute depths via BFS from entry
	m_depth[entry] = 0;
	std::vector<BasicBlock*> queue;
	queue.push_back(entry);
	size_t qi = 0;

	while (qi < queue.size())
	{
		BasicBlock* block = queue[qi++];
		int d = m_depth[block];

		for (BasicBlock* child : m_children[block])
		{
			m_depth[child] = d + 1;
			queue.push_back(child);
		}
	}

	m_computed = true;
}

void DominatorTree::dfs(BasicBlock* block)
{
	if (m_dfnum.count(block))
		return;

	int n = static_cast<int>(m_vertex.size());
	m_dfnum[block] = n;
	m_vertex.push_back(block);

	for (BasicBlock* succ : m_cfg.getSuccessors(block))
	{
		if (!m_dfnum.count(succ))
		{
			m_parent[succ] = block;
			dfs(succ);
		}
	}
}

BasicBlock* DominatorTree::eval(BasicBlock* v)
{
	if (!m_ancestor[v])
		return m_best[v];

	// Path compression
	std::vector<BasicBlock*> path;
	BasicBlock* u = v;

	while (m_ancestor[m_ancestor[u]])
	{
		path.push_back(u);
		u = m_ancestor[u];
	}

	// Compress path
	for (auto it = path.rbegin(); it != path.rend(); ++it)
	{
		BasicBlock* w = *it;
		if (m_dfnum[m_semi[m_best[m_ancestor[w]]]] < m_dfnum[m_semi[m_best[w]]])
			m_best[w] = m_best[m_ancestor[w]];
		m_ancestor[w] = m_ancestor[m_ancestor[w]];
	}

	return m_best[v];
}

void DominatorTree::link(BasicBlock* v, BasicBlock* w)
{
	m_ancestor[w] = v;
}

void DominatorTree::computeSemiDominators()
{
	// Process vertices in reverse DFS order (except entry)
	for (size_t i = m_vertex.size() - 1; i > 0; i--)
	{
		BasicBlock* w = m_vertex[i];
		BasicBlock* p = m_parent[w];

		// Step 2: Compute semi-dominator
		BasicBlock* semi = p;

		for (BasicBlock* v : m_cfg.getPredecessors(w))
		{
			BasicBlock* u;
			if (m_dfnum[v] <= m_dfnum[w])
				u = v;
			else
				u = m_semi[eval(v)];

			if (m_dfnum[u] < m_dfnum[semi])
				semi = u;
		}

		m_semi[w] = semi;
		m_bucket[semi].push_back(w);
		link(p, w);

		// Step 3: Implicitly define idom
		for (BasicBlock* v : m_bucket[p])
		{
			BasicBlock* u = eval(v);
			if (m_semi[u] == m_semi[v])
				m_idom[v] = p;
			else
				m_idom[v] = u;  // Implicit (will be fixed in step 4)
		}
		m_bucket[p].clear();
	}
}

void DominatorTree::computeImmediateDominators()
{
	// Step 4: Compute idom from implicit values
	for (size_t i = 1; i < m_vertex.size(); i++)
	{
		BasicBlock* w = m_vertex[i];
		if (m_idom[w] != m_semi[w])
			m_idom[w] = m_idom[m_idom[w]];
	}

	// Entry has no dominator
	m_idom[m_vertex[0]] = nullptr;
}

// ============================================================================
// Dominator queries
// ============================================================================

BasicBlock* DominatorTree::getImmediateDominator(BasicBlock* block)
{
	auto it = m_idom.find(block);
	return it != m_idom.end() ? it->second : nullptr;
}

const BasicBlock* DominatorTree::getImmediateDominator(const BasicBlock* block) const
{
	auto it = m_idom.find(const_cast<BasicBlock*>(block));
	return it != m_idom.end() ? it->second : nullptr;
}

std::vector<BasicBlock*> DominatorTree::getDominatees(BasicBlock* block)
{
	auto it = m_children.find(block);
	return it != m_children.end() ? it->second : std::vector<BasicBlock*>();
}

bool DominatorTree::dominates(BasicBlock* dominator, BasicBlock* dominated) const
{
	if (!dominator || !dominated)
		return false;
	if (dominator == dominated)
		return true;

	// Walk up from dominated to entry
	BasicBlock* current = const_cast<BasicBlock*>(dominated);
	while (current)
	{
		auto it = m_idom.find(current);
		if (it == m_idom.end())
			break;
		current = it->second;
		if (current == dominator)
			return true;
	}
	return false;
}

bool DominatorTree::strictlyDominates(BasicBlock* dominator, BasicBlock* dominated) const
{
	return dominator != dominated && dominates(dominator, dominated);
}

int DominatorTree::getDominatorDepth(BasicBlock* block) const
{
	auto it = m_depth.find(block);
	return it != m_depth.end() ? it->second : -1;
}

// ============================================================================
// Loop detection
// ============================================================================

std::vector<LoopInfo> DominatorTree::findNaturalLoops()
{
	if (m_loopsComputed)
		return m_loops;

	if (!m_computed)
		compute();

	m_loops.clear();
	m_blockToLoop.clear();

	// Find back-edges: edges from v to w where w dominates v
	for (BasicBlock* block : m_cfg.getBlocks())
	{
		for (BasicBlock* succ : m_cfg.getSuccessors(block))
		{
			if (dominates(succ, block))
			{
				// This is a back-edge from block to succ
				// succ is a loop header

				// Check if we already have a loop for this header
				LoopInfo* existingLoop = nullptr;
				for (auto& loop : m_loops)
				{
					if (loop.header == succ)
					{
						existingLoop = &loop;
						break;
					}
				}

				if (existingLoop)
				{
					// Add this back-edge source to existing loop
					existingLoop->backEdgeSources.insert(block);
					auto bodyBlocks = findLoopBody(succ, block);
					existingLoop->body.insert(bodyBlocks.begin(), bodyBlocks.end());
				}
				else
				{
					// Create new loop
					LoopInfo loop;
					loop.header = succ;
					loop.backEdgeSources.insert(block);
					loop.body = findLoopBody(succ, block);
					loop.body.insert(succ);  // Header is part of body
					m_loops.push_back(loop);
				}
			}
		}
	}

	// Find exit blocks for each loop
	for (auto& loop : m_loops)
	{
		for (BasicBlock* block : loop.body)
		{
			for (BasicBlock* succ : m_cfg.getSuccessors(block))
			{
				if (!loop.contains(succ))
					loop.exitBlocks.insert(block);
			}
		}
	}

	// Compute nesting levels
	// Sort loops by body size (smaller = more nested)
	std::sort(m_loops.begin(), m_loops.end(),
		[](const LoopInfo& a, const LoopInfo& b) {
			return a.body.size() < b.body.size();
		});

	for (size_t i = 0; i < m_loops.size(); i++)
	{
		for (size_t j = i + 1; j < m_loops.size(); j++)
		{
			// Check if loop i is nested in loop j
			if (m_loops[j].contains(m_loops[i].header))
			{
				m_loops[i].nestingLevel = std::max(m_loops[i].nestingLevel,
					m_loops[j].nestingLevel + 1);
			}
		}
	}

	// Build block to loop mapping (innermost loop)
	for (const auto& loop : m_loops)
	{
		for (BasicBlock* block : loop.body)
		{
			auto it = m_blockToLoop.find(block);
			if (it == m_blockToLoop.end() ||
				loop.nestingLevel > it->second->nestingLevel)
			{
				m_blockToLoop[block] = &loop;
			}
		}
	}

	m_loopsComputed = true;
	return m_loops;
}

std::set<BasicBlock*> DominatorTree::findLoopBody(BasicBlock* header, BasicBlock* backEdgeSource)
{
	std::set<BasicBlock*> body;
	std::stack<BasicBlock*> worklist;

	body.insert(header);
	if (backEdgeSource != header)
	{
		body.insert(backEdgeSource);
		worklist.push(backEdgeSource);
	}

	// Work backwards from back-edge source to header
	while (!worklist.empty())
	{
		BasicBlock* block = worklist.top();
		worklist.pop();

		for (BasicBlock* pred : m_cfg.getPredecessors(block))
		{
			if (!body.count(pred))
			{
				body.insert(pred);
				worklist.push(pred);
			}
		}
	}

	return body;
}

bool DominatorTree::isLoopHeader(BasicBlock* block) const
{
	for (const auto& loop : m_loops)
	{
		if (loop.header == block)
			return true;
	}
	return false;
}

const LoopInfo* DominatorTree::getLoopFor(BasicBlock* block) const
{
	auto it = m_blockToLoop.find(block);
	return it != m_blockToLoop.end() ? it->second : nullptr;
}

int DominatorTree::getLoopDepth(BasicBlock* block) const
{
	const LoopInfo* loop = getLoopFor(block);
	return loop ? loop->nestingLevel + 1 : 0;
}

}  // namespace Armv5Analysis
