/*
 * Call Graph Analysis
 *
 * Builds and analyzes inter-procedural call relationships.
 * Used for recursive function detection and call depth analysis.
 */

#pragma once

#include "binaryninjaapi.h"

#include <vector>
#include <map>
#include <set>
#include <memory>
#include <string>
#include <cstdint>

namespace Armv5Analysis
{

/**
 * Information about a call site
 */
struct CallSite
{
	uint64_t callerAddr;    // Address of calling function
	uint64_t callAddr;      // Address of call instruction
	uint64_t calleeAddr;    // Address of called function
	bool isDirect;          // Direct (BL) vs indirect (BLX Rn)
	bool isTailCall;        // Tail call (B instead of BL)
	bool isThumbCall;       // Is the call target in Thumb mode?
};

/**
 * A node in the call graph
 */
struct CallGraphNode
{
	uint64_t address;
	std::string name;
	bool isThumb = false;

	std::vector<uint64_t> callees;      // Functions this calls
	std::vector<uint64_t> callers;      // Functions that call this
	std::vector<CallSite> callSites;    // Detailed call site info

	// Computed properties
	int inDegree() const { return static_cast<int>(callers.size()); }
	int outDegree() const { return static_cast<int>(callees.size()); }
	bool isLeaf() const { return callees.empty(); }
	bool isRoot() const { return callers.empty(); }
	bool isRecursive = false;           // Calls itself (directly or indirectly)
};

/**
 * Call graph for inter-procedural analysis
 */
class CallGraph
{
public:
	explicit CallGraph(BinaryNinja::Ref<BinaryNinja::BinaryView> view);

	/**
	 * Build call graph from all known functions
	 */
	void build();

	/**
	 * Build call graph from specific function addresses
	 */
	void buildFromFunctions(const std::vector<uint64_t>& addresses);

	/**
	 * Add a single function to the graph
	 */
	void addFunction(uint64_t address);

	/**
	 * Is the graph built?
	 */
	bool isBuilt() const { return m_built; }

	// =========================================================================
	// Accessors
	// =========================================================================

	/**
	 * Get a node by function address
	 */
	CallGraphNode* getNode(uint64_t address);
	const CallGraphNode* getNode(uint64_t address) const;

	/**
	 * Get all nodes
	 */
	std::vector<CallGraphNode*> getNodes();
	std::vector<const CallGraphNode*> getNodes() const;

	/**
	 * Get root nodes (functions not called by others)
	 */
	std::vector<CallGraphNode*> getRoots();

	/**
	 * Get leaf nodes (functions that don't call others)
	 */
	std::vector<CallGraphNode*> getLeaves();

	/**
	 * Number of nodes
	 */
	size_t nodeCount() const { return m_nodes.size(); }

	// =========================================================================
	// Analysis
	// =========================================================================

	/**
	 * Get topologically sorted list of function addresses
	 * Returns empty if graph has cycles
	 */
	std::vector<uint64_t> topologicalSort();

	/**
	 * Find strongly connected components (mutually recursive functions)
	 */
	std::vector<std::vector<uint64_t>> findSCCs();

	/**
	 * Find all recursive functions (direct or mutual)
	 */
	std::vector<uint64_t> findRecursiveFunctions();

	/**
	 * Get maximum call depth from a function to any leaf
	 */
	int getCallDepth(uint64_t address);

	/**
	 * Get all functions reachable from the given address
	 */
	std::set<uint64_t> getReachable(uint64_t from);

	// =========================================================================
	// Path queries
	// =========================================================================

	/**
	 * Can we reach 'to' from 'from' via calls?
	 */
	bool canReach(uint64_t from, uint64_t to);

	/**
	 * Find a call path from 'from' to 'to'
	 * Returns empty if no path exists
	 */
	std::vector<uint64_t> findPath(uint64_t from, uint64_t to);

	// =========================================================================
	// Statistics
	// =========================================================================

	struct Stats
	{
		size_t totalNodes;
		size_t rootNodes;
		size_t leafNodes;
		size_t recursiveNodes;
		size_t totalCallSites;
		size_t directCalls;
		size_t indirectCalls;
		int maxCallDepth;
		double avgCallees;
		double avgCallers;
	};

	Stats getStats();

private:
	/**
	 * Scan a function for call sites
	 */
	void scanFunction(uint64_t address);

	/**
	 * Tarjan's algorithm for SCC detection
	 */
	void tarjanVisit(CallGraphNode* node, int& index,
		std::map<uint64_t, int>& indices,
		std::map<uint64_t, int>& lowlinks,
		std::map<uint64_t, bool>& onStack,
		std::vector<uint64_t>& stack,
		std::vector<std::vector<uint64_t>>& sccs);

	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	std::map<uint64_t, std::unique_ptr<CallGraphNode>> m_nodes;
	bool m_built = false;

	// Cached analysis results
	std::vector<std::vector<uint64_t>> m_sccs;
	bool m_sccsComputed = false;
};

}  // namespace Armv5Analysis
