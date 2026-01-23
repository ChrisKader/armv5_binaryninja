/*
 * Control Flow Graph - Implementation
 */

#include "control_flow_graph.h"

using namespace BinaryNinja;

namespace Armv5Analysis
{

// ============================================================================
// Constructor
// ============================================================================

ControlFlowGraph::ControlFlowGraph(Ref<BinaryView> view, uint64_t entryPoint, bool isThumb)
	: m_view(view)
	, m_entryPoint(entryPoint)
	, m_isThumb(isThumb)
{
}

// ============================================================================
// Build methods
// ============================================================================

bool ControlFlowGraph::build()
{
	return build(m_maxBlocks, m_maxInstructions);
}

bool ControlFlowGraph::build(size_t maxBlocks, size_t maxInstructions)
{
	m_maxBlocks = maxBlocks;
	m_maxInstructions = maxInstructions;
	m_totalInstructions = 0;
	m_blocks.clear();
	m_visited.clear();
	m_valid = false;
	m_errorMessage.clear();

	if (!m_view)
	{
		m_errorMessage = "No binary view";
		return false;
	}

	// Start exploration from entry point
	m_workList.push_back({m_entryPoint, m_isThumb});

	while (!m_workList.empty())
	{
		auto [addr, isThumb] = m_workList.back();
		m_workList.pop_back();

		// Skip if already visited
		if (m_visited.count(addr))
			continue;

		// Check limits
		if (m_blocks.size() >= m_maxBlocks)
		{
			m_errorMessage = "Block limit exceeded";
			return false;
		}

		// Explore this block
		exploreBlock(addr, isThumb);
	}

	// Mark entry block
	if (auto* entry = getBlock(m_entryPoint))
		entry->isEntryBlock = true;

	// Mark exit blocks
	for (auto& [addr, block] : m_blocks)
	{
		if (block->successors.empty() || block->endsWithReturn)
			block->isExitBlock = true;
	}

	// Validate: must have at least one block
	if (m_blocks.empty())
	{
		m_errorMessage = "No blocks found";
		return false;
	}

	// Validate: entry block must exist
	if (!getBlock(m_entryPoint))
	{
		m_errorMessage = "Entry block missing";
		return false;
	}

	m_valid = true;
	return true;
}

void ControlFlowGraph::exploreBlock(uint64_t start, bool isThumb)
{
	if (m_visited.count(start))
		return;

	// Check if this is inside an existing block - need to split
	BasicBlock* containingBlock = getBlockContaining(start);
	if (containingBlock && containingBlock->start != start)
	{
		splitBlockAt(start);
	}

	// If block already exists at this address, we're done
	if (m_blocks.count(start))
		return;

	// Create new block
	auto block = std::make_unique<BasicBlock>();
	block->start = start;
	block->isThumb = isThumb;

	uint64_t addr = start;
	bool terminated = false;

	while (!terminated && m_totalInstructions < m_maxInstructions)
	{
		// Check if we're entering another block's territory
		for (auto& [existingAddr, existingBlock] : m_blocks)
		{
			if (addr > existingBlock->start && addr < existingBlock->end)
			{
				// We're in the middle of another block - split it
				splitBlockAt(addr);
				// Fall through to this block
				block->end = addr;
				block->successors.push_back(addr);
				block->outEdges.push_back({addr, EdgeType::Fall, false});
				terminated = true;
				break;
			}
			else if (addr == existingAddr)
			{
				// We've reached the start of another block
				block->end = addr;
				block->successors.push_back(addr);
				block->outEdges.push_back({addr, EdgeType::Fall, false});
				existingBlock->predecessors.push_back(start);
				terminated = true;
				break;
			}
		}

		if (terminated)
			break;

		m_visited.insert(addr);

		InstructionInfo info;
		size_t length;

		if (!decodeInstruction(addr, isThumb, info, length))
		{
			// Invalid instruction - end block here
			block->end = addr;
			m_errorMessage = "Invalid instruction at 0x" + std::to_string(addr);
			break;
		}

		block->instructionCount++;
		m_totalInstructions++;

		// Check for call instructions
		if (info.branchCount > 0)
		{
			for (size_t i = 0; i < info.branchCount; i++)
			{
				if (info.branchType[i] == CallDestination)
				{
					block->containsCall = true;
					if (info.branchTarget[i] != 0)
						block->callTargets.push_back(info.branchTarget[i]);
				}
			}
		}

		// Check for terminator
		if (isTerminator(addr, isThumb, info))
		{
			block->end = addr + length;

			auto edges = getSuccessorEdges(addr, isThumb, info);
			for (const auto& edge : edges)
			{
				block->outEdges.push_back(edge);
				if (edge.type != EdgeType::Return && edge.type != EdgeType::Call)
				{
					block->successors.push_back(edge.target);
					block->branchTargets.push_back(edge.target);

					// Add to work list for exploration
					bool targetIsThumb = isThumb;
					// Check for mode switch (BLX, etc.)
					if (edge.target & 1)
						targetIsThumb = true;
					else if (info.branchCount > 0)
					{
						// Check if this is a BLX that switches modes
						for (size_t i = 0; i < info.branchCount; i++)
						{
							if (info.branchTarget[i] == edge.target)
							{
								// If branch arch differs, mode switch
								uint64_t ta = edge.target;
								auto targetArch = m_view->GetDefaultArchitecture()
									->GetAssociatedArchitectureByAddress(ta);
								if (targetArch)
								{
									std::string archName = targetArch->GetName();
									targetIsThumb = (archName.find('t') != std::string::npos ||
									                archName.find("thumb") != std::string::npos);
								}
								break;
							}
						}
					}

					m_workList.push_back({edge.target & ~1ULL, targetIsThumb});
				}

				// Mark block properties
				if (edge.type == EdgeType::Return)
					block->endsWithReturn = true;
				if (edge.type == EdgeType::Branch && !edge.isConditional &&
					edge.target != addr + length)
					block->endsWithTailCall = true;
			}

			terminated = true;
		}
		else
		{
			addr += length;
		}
	}

	if (!terminated)
	{
		// Ran out of instructions without terminator
		block->end = addr;
	}

	// Store the block
	uint64_t blockStart = block->start;
	m_blocks[blockStart] = std::move(block);

	// Update predecessor lists for successors
	BasicBlock* storedBlock = m_blocks[blockStart].get();
	for (uint64_t succ : storedBlock->successors)
	{
		if (auto* succBlock = getBlock(succ))
			succBlock->predecessors.push_back(blockStart);
	}
}

void ControlFlowGraph::splitBlockAt(uint64_t address)
{
	// Find the block containing this address
	BasicBlock* parent = nullptr;
	for (auto& [start, block] : m_blocks)
	{
		if (start < address && block->end > address)
		{
			parent = block.get();
			break;
		}
	}

	if (!parent)
		return;

	// Create new block from split point to old end
	auto newBlock = std::make_unique<BasicBlock>();
	newBlock->start = address;
	newBlock->end = parent->end;
	newBlock->isThumb = parent->isThumb;
	newBlock->successors = parent->successors;
	newBlock->outEdges = parent->outEdges;
	newBlock->endsWithReturn = parent->endsWithReturn;
	newBlock->endsWithTailCall = parent->endsWithTailCall;
	newBlock->containsCall = false;  // Will be recalculated if needed
	newBlock->predecessors.push_back(parent->start);

	// Update old block
	parent->end = address;
	parent->successors.clear();
	parent->successors.push_back(address);
	parent->outEdges.clear();
	parent->outEdges.push_back({address, EdgeType::Fall, false});
	parent->endsWithReturn = false;
	parent->endsWithTailCall = false;

	// Update successor predecessor lists
	for (uint64_t succ : newBlock->successors)
	{
		if (auto* succBlock = getBlock(succ))
		{
			auto& preds = succBlock->predecessors;
			std::replace(preds.begin(), preds.end(), parent->start, address);
		}
	}

	m_blocks[address] = std::move(newBlock);
}

bool ControlFlowGraph::isTerminator(uint64_t address, bool isThumb,
	InstructionInfo& info) const
{
	// Terminators: branches, returns, indirect jumps
	if (info.branchCount > 0)
		return true;

	// Check for POP {pc} which doesn't always show as branch in info
	// This is handled by the architecture's GetInstructionInfo

	return false;
}

std::vector<BasicBlock::Edge> ControlFlowGraph::getSuccessorEdges(uint64_t address,
	bool isThumb, const InstructionInfo& info) const
{
	std::vector<BasicBlock::Edge> edges;

	for (size_t i = 0; i < info.branchCount; i++)
	{
		BasicBlock::Edge edge;
		edge.target = info.branchTarget[i] & ~1ULL;  // Clear Thumb bit

		switch (info.branchType[i])
		{
		case UnconditionalBranch:
			edge.type = EdgeType::Branch;
			edge.isConditional = false;
			break;

		case TrueBranch:
		case FalseBranch:
			edge.type = EdgeType::Branch;
			edge.isConditional = true;
			break;

		case CallDestination:
			edge.type = EdgeType::Call;
			edge.isConditional = false;
			// Don't follow calls in intra-procedural CFG
			continue;

		case FunctionReturn:
			edge.type = EdgeType::Return;
			edge.isConditional = false;
			edge.target = 0;  // No target for returns
			break;

		case IndirectBranch:
			edge.type = EdgeType::Switch;
			edge.isConditional = false;
			break;

		default:
			edge.type = EdgeType::Branch;
			edge.isConditional = false;
			break;
		}

		edges.push_back(edge);
	}

	return edges;
}

bool ControlFlowGraph::decodeInstruction(uint64_t address, bool isThumb,
	InstructionInfo& info, size_t& length) const
{
	auto arch = getArch(isThumb);
	if (!arch)
		return false;

	size_t maxLen = isThumb ? 4 : 4;
	DataBuffer buf = m_view->ReadBuffer(address, maxLen);
	if (buf.GetLength() < (isThumb ? 2 : 4))
		return false;

	if (!arch->GetInstructionInfo(static_cast<const uint8_t*>(buf.GetData()),
		address, buf.GetLength(), info))
		return false;

	length = info.length;
	return length > 0;
}

Ref<Architecture> ControlFlowGraph::getArch(bool isThumb) const
{
	auto arch = m_view->GetDefaultArchitecture();
	if (!arch)
		return nullptr;

	if (isThumb)
	{
		uint64_t ta = m_entryPoint | 1;
		auto thumbArch = arch->GetAssociatedArchitectureByAddress(ta);
		if (thumbArch)
			return thumbArch;
	}

	return arch;
}

// ============================================================================
// Accessors
// ============================================================================

BasicBlock* ControlFlowGraph::getBlock(uint64_t address)
{
	auto it = m_blocks.find(address);
	return it != m_blocks.end() ? it->second.get() : nullptr;
}

const BasicBlock* ControlFlowGraph::getBlock(uint64_t address) const
{
	auto it = m_blocks.find(address);
	return it != m_blocks.end() ? it->second.get() : nullptr;
}

BasicBlock* ControlFlowGraph::getEntryBlock()
{
	return getBlock(m_entryPoint);
}

const BasicBlock* ControlFlowGraph::getEntryBlock() const
{
	return getBlock(m_entryPoint);
}

std::vector<BasicBlock*> ControlFlowGraph::getExitBlocks()
{
	std::vector<BasicBlock*> exits;
	for (auto& [addr, block] : m_blocks)
	{
		if (block->isExitBlock)
			exits.push_back(block.get());
	}
	return exits;
}

std::vector<const BasicBlock*> ControlFlowGraph::getExitBlocks() const
{
	std::vector<const BasicBlock*> exits;
	for (const auto& [addr, block] : m_blocks)
	{
		if (block->isExitBlock)
			exits.push_back(block.get());
	}
	return exits;
}

std::vector<BasicBlock*> ControlFlowGraph::getBlocks()
{
	std::vector<BasicBlock*> blocks;
	for (auto& [addr, block] : m_blocks)
		blocks.push_back(block.get());
	return blocks;
}

std::vector<const BasicBlock*> ControlFlowGraph::getBlocks() const
{
	std::vector<const BasicBlock*> blocks;
	for (const auto& [addr, block] : m_blocks)
		blocks.push_back(block.get());
	return blocks;
}

BasicBlock* ControlFlowGraph::getBlockContaining(uint64_t address)
{
	for (auto& [start, block] : m_blocks)
	{
		if (address >= block->start && address < block->end)
			return block.get();
	}
	return nullptr;
}

// ============================================================================
// Graph properties
// ============================================================================

size_t ControlFlowGraph::edgeCount() const
{
	size_t count = 0;
	for (const auto& [addr, block] : m_blocks)
		count += block->outEdges.size();
	return count;
}

size_t ControlFlowGraph::instructionCount() const
{
	size_t count = 0;
	for (const auto& [addr, block] : m_blocks)
		count += block->instructionCount;
	return count;
}

bool ControlFlowGraph::isReducible() const
{
	// Simple check: a CFG is reducible if there are no cross edges
	// (edges from a node to a non-ancestor in the DFS tree)
	// For now, return true as most ARM code is reducible
	// TODO: Implement proper reducibility check with DFS
	return true;
}

std::vector<BasicBlock*> ControlFlowGraph::getSuccessors(BasicBlock* block)
{
	std::vector<BasicBlock*> succs;
	if (!block)
		return succs;

	for (uint64_t addr : block->successors)
	{
		if (auto* succ = getBlock(addr))
			succs.push_back(succ);
	}
	return succs;
}

std::vector<BasicBlock*> ControlFlowGraph::getPredecessors(BasicBlock* block)
{
	std::vector<BasicBlock*> preds;
	if (!block)
		return preds;

	for (uint64_t addr : block->predecessors)
	{
		if (auto* pred = getBlock(addr))
			preds.push_back(pred);
	}
	return preds;
}

bool ControlFlowGraph::dominates(BasicBlock* dominator, BasicBlock* dominated) const
{
	// TODO: Implement dominator tree computation
	// For now, just return true if dominator is entry block
	if (!dominator || !dominated)
		return false;
	return dominator->isEntryBlock;
}

std::vector<uint64_t> ControlFlowGraph::getAllCallTargets() const
{
	std::set<uint64_t> targets;
	for (const auto& [addr, block] : m_blocks)
	{
		for (uint64_t target : block->callTargets)
			targets.insert(target);
	}
	return std::vector<uint64_t>(targets.begin(), targets.end());
}

int ControlFlowGraph::cyclomaticComplexity() const
{
	// M = E - N + 2P where P = connected components (usually 1)
	int E = static_cast<int>(edgeCount());
	int N = static_cast<int>(blockCount());
	return E - N + 2;
}

// ============================================================================
// Utilities
// ============================================================================

const char* EdgeTypeToString(EdgeType type)
{
	switch (type)
	{
	case EdgeType::Fall: return "Fall";
	case EdgeType::Branch: return "Branch";
	case EdgeType::Call: return "Call";
	case EdgeType::Return: return "Return";
	case EdgeType::Switch: return "Switch";
	case EdgeType::Exception: return "Exception";
	default: return "Unknown";
	}
}

}  // namespace Armv5Analysis
