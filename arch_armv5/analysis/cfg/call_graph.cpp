/*
 * Call Graph - Implementation
 */

#include "call_graph.h"

#include <algorithm>
#include <queue>
#include <stack>

using namespace BinaryNinja;

namespace Armv5Analysis
{

CallGraph::CallGraph(Ref<BinaryView> view)
	: m_view(view)
{
}

void CallGraph::build()
{
	if (!m_view)
		return;

	m_nodes.clear();
	m_sccsComputed = false;

	// Get all functions from the binary view
	for (auto& func : m_view->GetAnalysisFunctionList())
	{
		addFunction(func->GetStart());
	}

	m_built = true;
}

void CallGraph::buildFromFunctions(const std::vector<uint64_t>& addresses)
{
	m_nodes.clear();
	m_sccsComputed = false;

	for (uint64_t addr : addresses)
	{
		addFunction(addr);
	}

	m_built = true;
}

void CallGraph::addFunction(uint64_t address)
{
	if (m_nodes.count(address))
		return;

	// Create node
	auto node = std::make_unique<CallGraphNode>();
	node->address = address;

	// Get function info from BN
	if (auto func = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), address))
	{
		if (auto sym = func->GetSymbol())
			node->name = sym->GetShortName();
		else
			node->name = "sub_" + std::to_string(address);

		// Check if Thumb
		auto arch = func->GetArchitecture();
		if (arch)
		{
			std::string archName = arch->GetName();
			node->isThumb = (archName.find('t') != std::string::npos ||
			                archName.find("thumb") != std::string::npos);
		}
	}
	else
	{
		node->name = "sub_" + std::to_string(address);
	}

	m_nodes[address] = std::move(node);

	// Scan for call sites
	scanFunction(address);
}

void CallGraph::scanFunction(uint64_t address)
{
	auto func = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), address);
	if (!func)
		return;

	CallGraphNode* node = m_nodes[address].get();
	if (!node)
		return;

	// Get call sites from the function
	for (auto& callSite : func->GetCallSites())
	{
		uint64_t callAddr = callSite.addr;

		// Get the callees from this call site using ReferenceSource
		ReferenceSource refSrc;
		refSrc.func = callSite.func;
		refSrc.arch = callSite.arch;
		refSrc.addr = callAddr;

		auto targets = m_view->GetCallees(refSrc);
		for (uint64_t target : targets)
		{
			CallSite site;
			site.callerAddr = address;
			site.callAddr = callAddr;
			site.calleeAddr = target;
			site.isDirect = true;

			// Check if target is Thumb (bit 0 set or BLX instruction)
			site.isThumbCall = (target & 1) != 0;
			target = target & ~1ULL;  // Clear Thumb bit

			// Check for existing callee node, or create placeholder
			if (!m_nodes.count(target))
			{
				auto calleeNode = std::make_unique<CallGraphNode>();
				calleeNode->address = target;
				calleeNode->name = "sub_" + std::to_string(target);
				m_nodes[target] = std::move(calleeNode);
			}

			// Update relationships
			if (std::find(node->callees.begin(), node->callees.end(), target)
				== node->callees.end())
			{
				node->callees.push_back(target);
			}

			CallGraphNode* calleeNode = m_nodes[target].get();
			if (std::find(calleeNode->callers.begin(), calleeNode->callers.end(), address)
				== calleeNode->callers.end())
			{
				calleeNode->callers.push_back(address);
			}

			node->callSites.push_back(site);
		}
	}

	// Check for direct self-recursion
	if (std::find(node->callees.begin(), node->callees.end(), address) != node->callees.end())
	{
		node->isRecursive = true;
	}
}

// ============================================================================
// Accessors
// ============================================================================

CallGraphNode* CallGraph::getNode(uint64_t address)
{
	auto it = m_nodes.find(address);
	return it != m_nodes.end() ? it->second.get() : nullptr;
}

const CallGraphNode* CallGraph::getNode(uint64_t address) const
{
	auto it = m_nodes.find(address);
	return it != m_nodes.end() ? it->second.get() : nullptr;
}

std::vector<CallGraphNode*> CallGraph::getNodes()
{
	std::vector<CallGraphNode*> nodes;
	for (auto& kv : m_nodes)
		nodes.push_back(kv.second.get());
	return nodes;
}

std::vector<const CallGraphNode*> CallGraph::getNodes() const
{
	std::vector<const CallGraphNode*> nodes;
	for (const auto& kv : m_nodes)
		nodes.push_back(kv.second.get());
	return nodes;
}

std::vector<CallGraphNode*> CallGraph::getRoots()
{
	std::vector<CallGraphNode*> roots;
	for (auto& kv : m_nodes)
	{
		if (kv.second->isRoot())
			roots.push_back(kv.second.get());
	}
	return roots;
}

std::vector<CallGraphNode*> CallGraph::getLeaves()
{
	std::vector<CallGraphNode*> leaves;
	for (auto& kv : m_nodes)
	{
		if (kv.second->isLeaf())
			leaves.push_back(kv.second.get());
	}
	return leaves;
}

// ============================================================================
// Analysis
// ============================================================================

std::vector<uint64_t> CallGraph::topologicalSort()
{
	std::vector<uint64_t> result;
	std::map<uint64_t, int> inDegree;
	std::queue<uint64_t> queue;

	// Initialize in-degrees
	for (auto& kv : m_nodes)
	{
		inDegree[kv.first] = kv.second->inDegree();
		if (inDegree[kv.first] == 0)
			queue.push(kv.first);
	}

	while (!queue.empty())
	{
		uint64_t addr = queue.front();
		queue.pop();
		result.push_back(addr);

		CallGraphNode* node = m_nodes[addr].get();
		for (uint64_t callee : node->callees)
		{
			inDegree[callee]--;
			if (inDegree[callee] == 0)
				queue.push(callee);
		}
	}

	// If not all nodes are in result, there's a cycle
	if (result.size() != m_nodes.size())
		return {};

	return result;
}

std::vector<std::vector<uint64_t>> CallGraph::findSCCs()
{
	if (m_sccsComputed)
		return m_sccs;

	m_sccs.clear();

	std::map<uint64_t, int> indices;
	std::map<uint64_t, int> lowlinks;
	std::map<uint64_t, bool> onStack;
	std::vector<uint64_t> stack;
	int index = 0;

	for (auto& kv : m_nodes)
	{
		if (!indices.count(kv.first))
		{
			tarjanVisit(kv.second.get(), index, indices, lowlinks, onStack, stack, m_sccs);
		}
	}

	// Mark recursive functions (those in SCCs of size > 1, or self-loops)
	for (const auto& scc : m_sccs)
	{
		if (scc.size() > 1)
		{
			for (uint64_t addr : scc)
			{
				if (auto* node = getNode(addr))
					node->isRecursive = true;
			}
		}
	}

	m_sccsComputed = true;
	return m_sccs;
}

void CallGraph::tarjanVisit(CallGraphNode* node, int& index,
	std::map<uint64_t, int>& indices,
	std::map<uint64_t, int>& lowlinks,
	std::map<uint64_t, bool>& onStack,
	std::vector<uint64_t>& stack,
	std::vector<std::vector<uint64_t>>& sccs)
{
	indices[node->address] = index;
	lowlinks[node->address] = index;
	index++;
	stack.push_back(node->address);
	onStack[node->address] = true;

	for (uint64_t calleeAddr : node->callees)
	{
		if (!indices.count(calleeAddr))
		{
			if (auto* callee = getNode(calleeAddr))
			{
				tarjanVisit(callee, index, indices, lowlinks, onStack, stack, sccs);
				lowlinks[node->address] = std::min(lowlinks[node->address],
					lowlinks[calleeAddr]);
			}
		}
		else if (onStack[calleeAddr])
		{
			lowlinks[node->address] = std::min(lowlinks[node->address],
				indices[calleeAddr]);
		}
	}

	// If this is a root node, pop the SCC
	if (lowlinks[node->address] == indices[node->address])
	{
		std::vector<uint64_t> scc;
		uint64_t w;
		do
		{
			w = stack.back();
			stack.pop_back();
			onStack[w] = false;
			scc.push_back(w);
		} while (w != node->address);

		sccs.push_back(scc);
	}
}

std::vector<uint64_t> CallGraph::findRecursiveFunctions()
{
	findSCCs();  // Ensure SCCs are computed

	std::vector<uint64_t> recursive;
	for (auto& kv : m_nodes)
	{
		if (kv.second->isRecursive)
			recursive.push_back(kv.first);
	}
	return recursive;
}

int CallGraph::getCallDepth(uint64_t address)
{
	auto* node = getNode(address);
	if (!node)
		return 0;

	if (node->isLeaf())
		return 0;

	// BFS to find max depth
	std::map<uint64_t, int> depths;
	std::queue<uint64_t> queue;
	std::set<uint64_t> visited;

	depths[address] = 0;
	queue.push(address);

	int maxDepth = 0;

	while (!queue.empty())
	{
		uint64_t current = queue.front();
		queue.pop();

		if (visited.count(current))
			continue;
		visited.insert(current);

		auto* currentNode = getNode(current);
		if (!currentNode)
			continue;

		int d = depths[current];

		for (uint64_t callee : currentNode->callees)
		{
			if (!visited.count(callee))
			{
				depths[callee] = d + 1;
				maxDepth = std::max(maxDepth, d + 1);
				queue.push(callee);
			}
		}
	}

	return maxDepth;
}

std::set<uint64_t> CallGraph::getReachable(uint64_t from)
{
	std::set<uint64_t> reachable;
	std::queue<uint64_t> queue;

	queue.push(from);

	while (!queue.empty())
	{
		uint64_t current = queue.front();
		queue.pop();

		if (reachable.count(current))
			continue;
		reachable.insert(current);

		auto* node = getNode(current);
		if (!node)
			continue;

		for (uint64_t callee : node->callees)
		{
			if (!reachable.count(callee))
				queue.push(callee);
		}
	}

	return reachable;
}

bool CallGraph::canReach(uint64_t from, uint64_t to)
{
	return getReachable(from).count(to) > 0;
}

std::vector<uint64_t> CallGraph::findPath(uint64_t from, uint64_t to)
{
	std::map<uint64_t, uint64_t> parent;
	std::queue<uint64_t> queue;
	std::set<uint64_t> visited;

	queue.push(from);
	parent[from] = from;

	while (!queue.empty())
	{
		uint64_t current = queue.front();
		queue.pop();

		if (current == to)
		{
			// Reconstruct path
			std::vector<uint64_t> path;
			uint64_t c = to;
			while (c != from)
			{
				path.push_back(c);
				c = parent[c];
			}
			path.push_back(from);
			std::reverse(path.begin(), path.end());
			return path;
		}

		if (visited.count(current))
			continue;
		visited.insert(current);

		auto* node = getNode(current);
		if (!node)
			continue;

		for (uint64_t callee : node->callees)
		{
			if (!visited.count(callee) && !parent.count(callee))
			{
				parent[callee] = current;
				queue.push(callee);
			}
		}
	}

	return {};  // No path found
}

CallGraph::Stats CallGraph::getStats()
{
	Stats stats = {};

	stats.totalNodes = m_nodes.size();

	size_t totalCallees = 0;
	size_t totalCallers = 0;

	for (auto& kv : m_nodes)
	{
		CallGraphNode* node = kv.second.get();

		if (node->isRoot())
			stats.rootNodes++;
		if (node->isLeaf())
			stats.leafNodes++;
		if (node->isRecursive)
			stats.recursiveNodes++;

		totalCallees += node->callees.size();
		totalCallers += node->callers.size();
		stats.totalCallSites += node->callSites.size();

		for (const auto& site : node->callSites)
		{
			if (site.isDirect)
				stats.directCalls++;
			else
				stats.indirectCalls++;
		}
	}

	if (m_nodes.size() > 0)
	{
		stats.avgCallees = static_cast<double>(totalCallees) / m_nodes.size();
		stats.avgCallers = static_cast<double>(totalCallers) / m_nodes.size();
	}

	// Find max call depth
	for (auto& kv : m_nodes)
	{
		int depth = getCallDepth(kv.first);
		stats.maxCallDepth = std::max(stats.maxCallDepth, depth);
	}

	return stats;
}

}  // namespace Armv5Analysis
