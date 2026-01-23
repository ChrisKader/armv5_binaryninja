/*
 * Control Flow Graph for ARMv5 Analysis
 *
 * Provides CFG construction and analysis for function detection validation.
 * Supports both ARM and Thumb instruction modes with proper mode switching.
 */

#pragma once

#include "binaryninjaapi.h"

#include <vector>
#include <map>
#include <set>
#include <memory>
#include <cstdint>

namespace Armv5Analysis
{

/**
 * Edge types in the control flow graph
 */
enum class EdgeType
{
	Fall,       // Fall-through to next instruction
	Branch,     // Unconditional branch (B, B.cond)
	Call,       // Function call (BL, BLX) - not followed in intra-procedural CFG
	Return,     // Return (BX LR, POP {pc}, etc.)
	Switch,     // Switch/jump table indirect branch
	Exception   // Exception handler transition
};

/**
 * A basic block in the control flow graph
 */
struct BasicBlock
{
	uint64_t start;         // Start address (inclusive)
	uint64_t end;           // End address (exclusive - first byte after block)

	// Predecessors and successors
	std::vector<uint64_t> predecessors;
	std::vector<uint64_t> successors;

	// Edges with type information
	struct Edge
	{
		uint64_t target;
		EdgeType type;
		bool isConditional;
	};
	std::vector<Edge> outEdges;

	// Block properties
	bool isEntryBlock = false;
	bool isExitBlock = false;
	bool containsCall = false;
	bool containsIndirectBranch = false;
	bool endsWithReturn = false;
	bool endsWithTailCall = false;

	// Instruction information
	size_t instructionCount = 0;
	std::vector<uint64_t> callTargets;      // Direct call targets from this block
	std::vector<uint64_t> branchTargets;    // Branch targets

	// Mode information
	bool isThumb = false;

	// Size in bytes
	size_t size() const { return end - start; }
};

/**
 * Control Flow Graph for a single function or code region
 */
class ControlFlowGraph
{
public:
	/**
	 * Construct a CFG starting from the given entry point
	 */
	ControlFlowGraph(BinaryNinja::Ref<BinaryNinja::BinaryView> view,
		uint64_t entryPoint, bool isThumb);

	/**
	 * Build the CFG by following control flow from the entry point.
	 * Returns true if a valid CFG could be constructed.
	 */
	bool build();

	/**
	 * Build with limits to prevent runaway analysis
	 */
	bool build(size_t maxBlocks, size_t maxInstructions);

	// =========================================================================
	// Accessors
	// =========================================================================

	/**
	 * Get a basic block by start address
	 */
	BasicBlock* getBlock(uint64_t address);
	const BasicBlock* getBlock(uint64_t address) const;

	/**
	 * Get the entry block
	 */
	BasicBlock* getEntryBlock();
	const BasicBlock* getEntryBlock() const;

	/**
	 * Get all exit blocks (blocks that return or have no successors)
	 */
	std::vector<BasicBlock*> getExitBlocks();
	std::vector<const BasicBlock*> getExitBlocks() const;

	/**
	 * Get all blocks in the CFG
	 */
	std::vector<BasicBlock*> getBlocks();
	std::vector<const BasicBlock*> getBlocks() const;

	/**
	 * Get block containing the given address
	 */
	BasicBlock* getBlockContaining(uint64_t address);

	// =========================================================================
	// Graph properties
	// =========================================================================

	size_t blockCount() const { return m_blocks.size(); }
	size_t edgeCount() const;
	size_t instructionCount() const;

	/**
	 * Is this a reducible flow graph?
	 * (All loops have a single entry point)
	 */
	bool isReducible() const;

	/**
	 * Get the entry point address
	 */
	uint64_t entryPoint() const { return m_entryPoint; }

	/**
	 * Is the entry point in Thumb mode?
	 */
	bool isThumb() const { return m_isThumb; }

	/**
	 * Did construction succeed?
	 */
	bool isValid() const { return m_valid; }

	/**
	 * Get error message if construction failed
	 */
	const std::string& errorMessage() const { return m_errorMessage; }

	// =========================================================================
	// Queries
	// =========================================================================

	/**
	 * Get immediate successors of a block
	 */
	std::vector<BasicBlock*> getSuccessors(BasicBlock* block);

	/**
	 * Get immediate predecessors of a block
	 */
	std::vector<BasicBlock*> getPredecessors(BasicBlock* block);

	/**
	 * Check if one block dominates another
	 * (Requires dominator tree to be computed first)
	 */
	bool dominates(BasicBlock* dominator, BasicBlock* dominated) const;

	/**
	 * Find all call targets discovered during CFG construction
	 */
	std::vector<uint64_t> getAllCallTargets() const;

	/**
	 * Compute cyclomatic complexity: E - N + 2
	 * Where E = edges, N = nodes
	 */
	int cyclomaticComplexity() const;

private:
	// =========================================================================
	// Construction helpers
	// =========================================================================

	/**
	 * Explore a block starting at the given address
	 */
	void exploreBlock(uint64_t start, bool isThumb);

	/**
	 * Split a block at the given address (for branch targets)
	 */
	void splitBlockAt(uint64_t address);

	/**
	 * Check if instruction at address is a terminator
	 */
	bool isTerminator(uint64_t address, bool isThumb,
		BinaryNinja::InstructionInfo& info) const;

	/**
	 * Get the successor info for a terminating instruction
	 */
	std::vector<BasicBlock::Edge> getSuccessorEdges(uint64_t address, bool isThumb,
		const BinaryNinja::InstructionInfo& info) const;

	/**
	 * Decode an instruction at the given address
	 */
	bool decodeInstruction(uint64_t address, bool isThumb,
		BinaryNinja::InstructionInfo& info, size_t& length) const;

	/**
	 * Get the architecture for the given mode
	 */
	BinaryNinja::Ref<BinaryNinja::Architecture> getArch(bool isThumb) const;

	// =========================================================================
	// Data members
	// =========================================================================

	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	uint64_t m_entryPoint;
	bool m_isThumb;

	// Basic blocks by start address
	std::map<uint64_t, std::unique_ptr<BasicBlock>> m_blocks;

	// Addresses we've visited during exploration
	std::set<uint64_t> m_visited;

	// Work list for exploration
	std::vector<std::pair<uint64_t, bool>> m_workList;  // (address, isThumb)

	// Construction limits
	size_t m_maxBlocks = 500;
	size_t m_maxInstructions = 10000;
	size_t m_totalInstructions = 0;

	// Status
	bool m_valid = false;
	std::string m_errorMessage;
};

/**
 * Convert edge type to string for debugging
 */
const char* EdgeTypeToString(EdgeType type);

}  // namespace Armv5Analysis
