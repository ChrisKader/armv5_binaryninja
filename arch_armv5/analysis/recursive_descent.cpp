/*
 * Recursive Descent Analyzer - Implementation
 */

#include "recursive_descent.h"
#include "common/armv5_utils.h"

#include <algorithm>

using namespace BinaryNinja;

namespace Armv5Analysis
{

RecursiveDescentAnalyzer::RecursiveDescentAnalyzer(Ref<BinaryView> view)
	: m_view(view)
{
	m_logger = LogRegistry::CreateLogger("RecursiveDescentAnalyzer");
}

size_t RecursiveDescentAnalyzer::analyze()
{
	return analyze(m_settings);
}

size_t RecursiveDescentAnalyzer::analyze(const RecursiveDescentSettings& settings)
{
	m_settings = settings;
	m_results.clear();
	m_queued.clear();
	m_stats = Stats{};

	// Clear work queue
	while (!m_workQueue.empty())
		m_workQueue.pop();

	// Collect entry points
	collectEntryPoints();

	if (!reportProgress("Starting analysis..."))
		return 0;

	// Process work queue
	while (!m_workQueue.empty())
	{
		// Check limits
		if (m_results.size() >= m_settings.maxFunctionsToDiscover)
		{
			m_logger->LogInfo("Reached maximum function limit");
			break;
		}

		if (m_stats.totalInstructions >= m_settings.maxTotalInstructions)
		{
			m_logger->LogInfo("Reached maximum instruction limit");
			break;
		}

		// Get next entry point
		auto [address, isThumb, fromCall] = m_workQueue.front();
		m_workQueue.pop();

		// Skip if already analyzed
		if (m_results.count(address))
			continue;

		// Skip if inside known function
		if (isInsideKnownFunction(address))
			continue;

		// Analyze this entry point
		analyzeEntryPoint(address, isThumb);

		// Report progress
		if (!reportProgress("Analyzing 0x" + std::to_string(address)))
			break;
	}

	m_logger->LogInfo("Recursive descent complete: %zu functions discovered",
		m_results.size());

	return m_results.size();
}

void RecursiveDescentAnalyzer::collectEntryPoints()
{
	// Add explicit entry points first
	for (const auto& [addr, isThumb] : m_explicitEntryPoints)
	{
		if (!m_queued.count(addr))
		{
			m_workQueue.push({addr, isThumb, false});
			m_queued.insert(addr);
		}
	}

	// Binary entry point
	if (m_settings.useEntryPoint)
	{
		uint64_t entry = m_view->GetEntryPoint();
		if (entry != 0 && !m_queued.count(entry))
		{
			// Determine mode from entry point
			bool isThumb = (entry & 1) != 0;
			entry &= ~1ULL;

			m_workQueue.push({entry, isThumb, false});
			m_queued.insert(entry);
			m_stats.entryPointsProcessed++;
		}
	}

	// Existing functions
	if (m_settings.useExistingFunctions)
	{
		for (auto& func : m_view->GetAnalysisFunctionList())
		{
			uint64_t addr = func->GetStart();
			if (!m_queued.count(addr))
			{
				// Determine mode from architecture
				bool isThumb = false;
				auto arch = func->GetArchitecture();
				if (arch)
				{
					std::string archName = arch->GetName();
					isThumb = (archName.find('t') != std::string::npos ||
					          archName.find("thumb") != std::string::npos);
				}

				m_workQueue.push({addr, isThumb, false});
				m_queued.insert(addr);
				m_stats.entryPointsProcessed++;
			}
		}
	}

	// Symbols
	if (m_settings.useSymbols)
	{
		for (auto& sym : m_view->GetSymbols())
		{
			if (sym->GetType() == FunctionSymbol ||
			    sym->GetType() == ImportedFunctionSymbol)
			{
				uint64_t addr = sym->GetAddress();
				if (!m_queued.count(addr) && isExecutable(addr))
				{
					bool isThumb = (addr & 1) != 0;
					addr &= ~1ULL;

					m_workQueue.push({addr, isThumb, false});
					m_queued.insert(addr);
					m_stats.entryPointsProcessed++;
				}
			}
		}
	}

	// Vector table (exception handlers)
	if (m_settings.useVectorTable)
	{
		// Look for vector table at common locations
		std::vector<uint64_t> vectorTableAddrs;

		// Try to find segments that might contain vector table
		for (auto& seg : m_view->GetSegments())
		{
			if (seg->GetStart() == 0 || seg->GetStart() == 0x08000000)
			{
				vectorTableAddrs.push_back(seg->GetStart());
			}
		}

		// Also check start of first executable segment
		for (auto& seg : m_view->GetSegments())
		{
			if (seg->GetFlags() & SegmentExecutable)
			{
				vectorTableAddrs.push_back(seg->GetStart());
				break;
			}
		}

		for (uint64_t vtAddr : vectorTableAddrs)
		{
			// Read first 16 entries (ARM Cortex-M vector table)
			for (int i = 0; i < 16; i++)
			{
				DataBuffer buf = m_view->ReadBuffer(vtAddr + i * 4, 4);
				if (buf.GetLength() < 4)
					continue;

				const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
				uint32_t handler = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);

				// Skip null/invalid handlers
				if (handler == 0 || handler == 0xFFFFFFFF)
					continue;

				// Check for Thumb bit and validate
				bool isThumb = (handler & 1) != 0;
				uint64_t addr = handler & ~1ULL;

				if (isExecutable(addr) && !m_queued.count(addr))
				{
					m_workQueue.push({addr, isThumb, false});
					m_queued.insert(addr);
					m_stats.entryPointsProcessed++;
				}
			}
		}
	}

	m_logger->LogInfo("Collected %zu entry points", m_queued.size());
}

void RecursiveDescentAnalyzer::analyzeEntryPoint(uint64_t address, bool isThumb)
{
	// Skip if not executable
	if (!isExecutable(address))
		return;

	// Create function entry
	AnalyzedFunction func;
	func.entryPoint = address;
	func.isThumb = isThumb;

	// Build and analyze CFG
	if (m_settings.validateWithCfg)
	{
		if (!buildAndAnalyzeCfg(func))
		{
			m_stats.failedCfgBuilds++;
			// Still add with low confidence if requested
			func.confidence = 0.1;
			func.analysisNotes = "CFG construction failed";
		}
	}

	// Calculate confidence
	func.confidence = calculateConfidence(func);

	// Add call targets to work queue
	if (m_settings.followCalls)
	{
		for (uint64_t target : func.callTargets)
		{
			if (!m_queued.count(target) && isExecutable(target))
			{
				bool targetThumb = determineTargetMode(address, target, isThumb);
				m_workQueue.push({target & ~1ULL, targetThumb, true});
				m_queued.insert(target & ~1ULL);

				// Track mode changes
				if (targetThumb != isThumb)
				{
					func.modeChanges.push_back({address, target});
					if (isThumb)
						func.hasThumbToArmCalls = true;
					else
						func.hasArmToThumbCalls = true;
					m_stats.interworkingCalls++;
				}
			}
		}
	}

	// Add tail call targets
	if (m_settings.followTailCalls)
	{
		for (uint64_t target : func.tailCallTargets)
		{
			if (!m_queued.count(target) && isExecutable(target))
			{
				bool targetThumb = determineTargetMode(address, target, isThumb);
				m_workQueue.push({target & ~1ULL, targetThumb, false});
				m_queued.insert(target & ~1ULL);
			}
		}
	}

	// Check for self-recursion
	if (std::find(func.callTargets.begin(), func.callTargets.end(), address)
		!= func.callTargets.end())
	{
		func.appearsRecursive = true;
	}

	// Update stats
	m_stats.functionsDiscovered++;
	m_stats.totalInstructions += func.instructionCount;
	m_stats.totalBlocks += func.blockCount;
	if (isThumb)
		m_stats.thumbFunctions++;
	else
		m_stats.armFunctions++;

	// Store result
	m_results[address] = std::move(func);
}

bool RecursiveDescentAnalyzer::buildAndAnalyzeCfg(AnalyzedFunction& func)
{
	func.cfg = std::make_unique<ControlFlowGraph>(m_view, func.entryPoint, func.isThumb);

	if (!func.cfg->build(m_settings.maxBlocksPerFunction, m_settings.maxInstructionsPerFunction))
	{
		func.cfgValid = false;
		func.analysisNotes = func.cfg->errorMessage();
		return false;
	}

	func.cfgValid = true;
	func.blockCount = func.cfg->blockCount();
	func.instructionCount = func.cfg->instructionCount();
	func.cyclomaticComplexity = func.cfg->cyclomaticComplexity();

	// Calculate function boundaries
	func.startAddress = UINT64_MAX;
	func.endAddress = 0;

	auto blocks = func.cfg->getBlocks();
	for (const auto* block : blocks)
	{
		if (block->start < func.startAddress)
			func.startAddress = block->start;
		if (block->end > func.endAddress)
			func.endAddress = block->end;

		// Collect call targets
		for (uint64_t target : block->callTargets)
		{
			if (std::find(func.callTargets.begin(), func.callTargets.end(), target)
				== func.callTargets.end())
			{
				func.callTargets.push_back(target);
			}
		}

		// Check for indirect branches
		if (block->containsIndirectBranch)
			func.hasIndirectBranch = true;

		// Check for returns
		if (block->endsWithReturn)
			func.hasReturn = true;

		// Check for tail calls
		if (block->endsWithTailCall)
		{
			func.hasTailCall = true;
			for (const auto& edge : block->outEdges)
			{
				if (edge.type == EdgeType::Branch && !edge.isConditional &&
				    edge.target != 0 && edge.target < func.startAddress)
				{
					// This might be a tail call to another function
					func.tailCallTargets.push_back(edge.target);
				}
			}
		}
	}

	// Check if leaf function
	func.isLeaf = func.callTargets.empty();

	return true;
}

double RecursiveDescentAnalyzer::calculateConfidence(const AnalyzedFunction& func)
{
	double score = 0.3;  // Base score

	// Valid CFG is a strong indicator
	if (func.cfgValid)
	{
		score += m_settings.validCfgBonus;

		// Multiple blocks is good
		if (func.blockCount >= 2)
			score += 0.1;

		// Having exit blocks is good
		if (func.hasReturn)
			score += m_settings.returnBonus;
	}

	// Being a call target is very reliable
	// (This is set by the caller when adding from a call)
	// We check if any existing result calls this address
	for (const auto& [addr, other] : m_results)
	{
		if (std::find(other.callTargets.begin(), other.callTargets.end(), func.entryPoint)
			!= other.callTargets.end())
		{
			score += m_settings.callTargetBonus;
			break;
		}
	}

	// Leaf functions are common
	if (func.isLeaf && func.hasReturn)
		score += 0.1;

	// Tail calls are legitimate
	if (func.hasTailCall)
		score += 0.05;

	// Indirect branches might indicate switch statements (good) or obfuscation (bad)
	// Slight penalty
	if (func.hasIndirectBranch)
		score -= 0.05;

	// Very small functions might be padding or data
	if (func.instructionCount <= 2)
		score -= 0.2;

	// Clamp to [0, 1]
	return std::max(0.0, std::min(1.0, score));
}

bool RecursiveDescentAnalyzer::isExecutable(uint64_t address) const
{
	for (auto& seg : m_view->GetSegments())
	{
		if (address >= seg->GetStart() && address < seg->GetEnd())
		{
			return (seg->GetFlags() & SegmentExecutable) != 0;
		}
	}
	return false;
}

bool RecursiveDescentAnalyzer::isInsideKnownFunction(uint64_t address) const
{
	// TODO: Performance optimization - this is O(n) for each call.
	// For large binaries with many functions, consider using an interval tree
	// data structure for O(log n) range queries. This would require:
	// 1. Building the interval tree once from m_results and BN functions
	// 2. Invalidating/updating when new functions are discovered
	// See: https://en.wikipedia.org/wiki/Interval_tree

	// Check against results
	for (const auto& [entryAddr, func] : m_results)
	{
		if (address > func.startAddress && address < func.endAddress)
			return true;
	}

	// Check against existing BN functions
	for (auto& func : m_view->GetAnalysisFunctionList())
	{
		uint64_t start = func->GetStart();
		// Get function ranges
		for (auto& range : func->GetAddressRanges())
		{
			if (address >= range.start && address < range.end)
				return true;
		}
	}

	return false;
}

bool RecursiveDescentAnalyzer::determineTargetMode(uint64_t callSite, uint64_t target,
	bool currentMode) const
{
	// If target has Thumb bit set, it's definitely Thumb
	if (target & 1)
		return true;

	// Try to decode the call instruction to see if it's BLX (mode switch)
	auto arch = m_view->GetDefaultArchitecture();
	if (!arch)
		return currentMode;

	// Get the instruction at call site
	DataBuffer buf = m_view->ReadBuffer(callSite, 4);
	if (buf.GetLength() < 2)
		return currentMode;

	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());

	if (currentMode)  // Thumb mode
	{
		// Check for BLX (Thumb-2)
		uint16_t instr = data[0] | (data[1] << 8);
		if ((instr & 0xF800) == 0xF000)
		{
			// 32-bit Thumb instruction
			if (buf.GetLength() >= 4)
			{
				uint16_t instr2 = data[2] | (data[3] << 8);
				// BLX imm has bit 12 of second halfword clear
				if ((instr2 & 0x1000) == 0)
					return false;  // Switches to ARM
			}
		}
	}
	else  // ARM mode
	{
		// Check for BLX instruction
		uint32_t instr = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
		// BLX immediate: 1111 101H xxxx xxxx xxxx xxxx xxxx xxxx
		if ((instr & 0xFE000000) == 0xFA000000)
			return true;  // Switches to Thumb
	}

	return currentMode;
}

bool RecursiveDescentAnalyzer::reportProgress(const std::string& status)
{
	if (!m_progressCallback)
		return true;

	return m_progressCallback(m_results.size(), m_workQueue.size(), status);
}

void RecursiveDescentAnalyzer::addEntryPoint(uint64_t address, bool isThumb)
{
	m_explicitEntryPoints.push_back({address, isThumb});
}

void RecursiveDescentAnalyzer::clearEntryPoints()
{
	m_explicitEntryPoints.clear();
}

const AnalyzedFunction* RecursiveDescentAnalyzer::getFunction(uint64_t address) const
{
	auto it = m_results.find(address);
	return it != m_results.end() ? &it->second : nullptr;
}

size_t RecursiveDescentAnalyzer::applyToView(double minConfidence)
{
	size_t created = 0;
	Ref<Platform> defaultPlat = m_view->GetDefaultPlatform();
	Ref<Architecture> defaultArch = m_view->GetDefaultArchitecture();

	for (const auto& [address, func] : m_results)
	{
		if (func.confidence < minConfidence)
			continue;

		// Validate alignment: ARM requires 4-byte, Thumb requires 2-byte
		uint64_t funcAddr = address & ~1ULL;  // Clear potential Thumb bit
		if (!func.isThumb && (funcAddr & 3))
			continue;  // ARM function at non-4-byte-aligned address - skip
		if (func.isThumb && (funcAddr & 1))
			continue;  // Thumb function at odd address - skip

		// Use the correct platform based on isThumb flag
		Ref<Platform> platform = defaultPlat;
		if (func.isThumb && defaultArch)
		{
			uint64_t thumbAddr = address | 1;
			Ref<Architecture> thumbArch = defaultArch->GetAssociatedArchitectureByAddress(thumbAddr);
			if (thumbArch && thumbArch != defaultArch)
			{
				Ref<Platform> thumbPlat = defaultPlat->GetRelatedPlatform(thumbArch);
				if (thumbPlat)
					platform = thumbPlat;
			}
		}

		// Skip if function already exists
		if (m_view->GetAnalysisFunction(platform, funcAddr))
			continue;

		// Validate the function start (checks for strings, data regions, padding, etc.)
		if (!armv5::IsValidFunctionStart(m_view, platform, funcAddr, m_logger.GetPtr(), "RecursiveDescent"))
		{
			m_logger->LogDebug("RecursiveDescent: Rejected 0x%llx - failed validation",
				(unsigned long long)funcAddr);
			continue;
		}

		// Create the function
		m_view->CreateUserFunction(platform, funcAddr);
		created++;
	}

	m_logger->LogInfo("Created %zu functions from recursive descent analysis", created);
	return created;
}

}  // namespace Armv5Analysis
