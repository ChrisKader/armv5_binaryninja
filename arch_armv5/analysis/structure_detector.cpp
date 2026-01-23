/*
 * Structure Detector Implementation
 */

#include "structure_detector.h"
#include <algorithm>
#include <cstring>

using namespace BinaryNinja;

namespace
{
// Safe unaligned read for uint32_t - avoids undefined behavior on strict alignment architectures
inline uint32_t ReadU32Unaligned(const void* data)
{
	uint32_t value;
	std::memcpy(&value, data, sizeof(value));
	return value;
}
}

namespace Armv5Analysis
{

StructureDetector::StructureDetector(BinaryView* view)
	: m_view(view)
	, m_imageBase(0)
	, m_imageEnd(0)
{
	m_stats = {};
	
	// Build code/data region sets
	for (const auto& seg : m_view->GetSegments())
	{
		if (seg->GetFlags() & SegmentExecutable)
		{
			for (uint64_t a = seg->GetStart(); a < seg->GetEnd(); a += 0x1000)
				m_codeRegions.insert(a & ~0xFFFULL);
		}
		else if (seg->GetFlags() & SegmentReadable)
		{
			for (uint64_t a = seg->GetStart(); a < seg->GetEnd(); a += 0x1000)
				m_dataRegions.insert(a & ~0xFFFULL);
		}
		
		if (m_imageBase == 0 || seg->GetStart() < m_imageBase)
			m_imageBase = seg->GetStart();
		if (seg->GetEnd() > m_imageEnd)
			m_imageEnd = seg->GetEnd();
	}
}

const char* StructureDetector::TypeToString(StructureType type)
{
	switch (type)
	{
	case StructureType::VTable: return "VTable";
	case StructureType::JumpTable: return "Jump Table";
	case StructureType::FunctionTable: return "Function Table";
	case StructureType::PointerArray: return "Pointer Array";
	case StructureType::IntegerArray: return "Integer Array";
	case StructureType::StringTable: return "String Table";
	case StructureType::HandlerTable: return "Handler Table";
	case StructureType::StructArray: return "Struct Array";
	default: return "Unknown";
	}
}

bool StructureDetector::isCodePointer(uint64_t value) const
{
	if (value < m_imageBase || value >= m_imageEnd)
		return false;
	
	// Check if in code region
	uint64_t page = value & ~0xFFFULL;
	if (m_codeRegions.count(page))
		return true;
	
	// Check if it's a known function
	auto func = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), value);
	if (func)
		return true;
	
	// Check Thumb bit
	if (value & 1)
	{
		uint64_t addr = value & ~1ULL;
		page = addr & ~0xFFFULL;
		return m_codeRegions.count(page) > 0;
	}
	
	return false;
}

bool StructureDetector::isDataPointer(uint64_t value) const
{
	if (value < m_imageBase || value >= m_imageEnd)
		return false;
	
	uint64_t page = value & ~0xFFFULL;
	return m_dataRegions.count(page) > 0;
}

bool StructureDetector::isValidPointer(uint64_t value) const
{
	return isCodePointer(value) || isDataPointer(value);
}

std::string StructureDetector::resolveSymbol(uint64_t addr) const
{
	auto sym = m_view->GetSymbolByAddress(addr);
	if (sym)
		return sym->GetShortName();
	
	auto func = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), addr);
	if (func)
	{
		auto funcSym = func->GetSymbol();
		if (funcSym)
			return funcSym->GetShortName();
	}
	
	return "";
}

double StructureDetector::calculateConfidence(const DetectedStructure& s, const StructureDetectionSettings& settings) const
{
	double conf = 0.5;
	
	// More elements = higher confidence
	if (s.elementCount >= 5) conf += 0.1;
	if (s.elementCount >= 10) conf += 0.1;
	if (s.elementCount >= 20) conf += 0.05;
	
	// Has xrefs
	if (!s.xrefSources.empty()) conf += 0.15;
	
	// Aligned address
	if ((s.address & 3) == 0) conf += 0.05;
	
	// Type-specific bonuses
	switch (s.type)
	{
	case StructureType::VTable:
		// All elements are code pointers - very high confidence
		conf += 0.2;
		break;
	case StructureType::JumpTable:
		// Referenced from code, targets in same function
		conf += 0.15;
		break;
	case StructureType::FunctionTable:
		conf += 0.1;
		break;
	default:
		break;
	}
	
	// Has resolved symbols
	int namedCount = 0;
	for (const auto& name : s.elementNames)
		if (!name.empty()) namedCount++;
	if (namedCount > 0)
		conf += 0.1 * std::min(1.0, namedCount / 5.0);
	
	return std::min(1.0, std::max(0.0, conf));
}

void StructureDetector::scanForVtables(const StructureDetectionSettings& settings, std::vector<DetectedStructure>& results)
{
	// VTables are arrays of function pointers at aligned addresses
	// They're typically in data sections and all elements point to code
	
	for (const auto& seg : m_view->GetSegments())
	{
		// VTables are usually in read-only data
		if (seg->GetFlags() & SegmentExecutable)
			continue;
		if (!(seg->GetFlags() & SegmentReadable))
			continue;
		
		uint64_t addr = seg->GetStart();
		addr = (addr + 3) & ~3ULL;  // Align to 4 bytes
		
		while (addr + 4 <= seg->GetEnd())
		{
			// Read potential function pointer
			DataBuffer buf = m_view->ReadBuffer(addr, 4);
			if (buf.GetLength() < 4)
			{
				addr += 4;
				continue;
			}
			
			uint32_t value = ReadU32Unaligned(buf.GetData());
			
			if (!isCodePointer(value))
			{
				addr += 4;
				continue;
			}
			
			// Found a code pointer - check if it's the start of a vtable
			DetectedStructure vtable;
			vtable.address = addr;
			vtable.type = StructureType::VTable;
			vtable.elementSize = 4;
			
			uint64_t scanAddr = addr;
			while (scanAddr + 4 <= seg->GetEnd() && vtable.elements.size() < settings.maxElements)
			{
				buf = m_view->ReadBuffer(scanAddr, 4);
				if (buf.GetLength() < 4)
					break;
				
				uint32_t ptr = ReadU32Unaligned(buf.GetData());
				
				if (!isCodePointer(ptr))
					break;
				
				vtable.elements.push_back(ptr);
				vtable.functionTargets.push_back(ptr & ~1ULL);  // Strip Thumb bit
				vtable.elementNames.push_back(resolveSymbol(ptr & ~1ULL));
				
				scanAddr += 4;
			}
			
			if (vtable.elements.size() >= settings.minElements)
			{
				vtable.elementCount = vtable.elements.size();
				vtable.size = vtable.elementCount * 4;
				vtable.description = "C++ virtual function table";
				vtable.isNew = true;  // TODO: check existing types
				
				// Get xrefs to this table
				auto refs = m_view->GetCodeReferences(addr);
				for (const auto& ref : refs)
					vtable.xrefSources.push_back(ref.addr);
				
				vtable.confidence = calculateConfidence(vtable, settings);
				
				// Generate type name
				if (!vtable.elementNames.empty() && !vtable.elementNames[0].empty())
				{
					std::string baseName = vtable.elementNames[0];
					size_t pos = baseName.find("::");
					if (pos != std::string::npos)
						vtable.inferredTypeName = baseName.substr(0, pos) + "_vtable";
					else
						vtable.inferredTypeName = "vtable_" + std::to_string(addr);
				}
				else
				{
					vtable.inferredTypeName = "vtable_" + std::to_string(addr);
				}
				
				if (vtable.confidence >= settings.minConfidence)
				{
					results.push_back(vtable);
					m_stats.vtables++;
					m_stats.totalFunctionsDiscovered += vtable.functionTargets.size();
				}
				
				// Skip past this vtable
				addr = scanAddr;
			}
			else
			{
				addr += 4;
			}
		}
	}
}

void StructureDetector::scanForJumpTables(const StructureDetectionSettings& settings, std::vector<DetectedStructure>& results)
{
	// Jump tables are used in switch statements
	// Pattern: TBB/TBH instructions or computed branches
	// The table contains offsets or addresses to case handlers
	
	// Look for ADD PC, PC, Rn patterns (common in ARM)
	for (const auto& func : m_view->GetAnalysisFunctionList())
	{
		// Check for indirect branches in function
		auto llil = func->GetLowLevelIL();
		if (!llil)
			continue;
		
		// For now, look for data references that could be jump tables
		// A proper implementation would analyze the actual branch instructions
	}
	
	// Also scan for tables of code pointers within functions
	for (const auto& seg : m_view->GetSegments())
	{
		if (!(seg->GetFlags() & SegmentExecutable))
			continue;
		
		// Look for embedded tables (often after functions)
		// These are sequences of code addresses within the same segment
		uint64_t addr = seg->GetStart();
		addr = (addr + 3) & ~3ULL;
		
		while (addr + 4 <= seg->GetEnd())
		{
			// Skip if this is inside a function
			auto func = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), addr);
			if (func && addr != func->GetStart())
			{
				addr += 4;
				continue;
			}
			
			DataBuffer buf = m_view->ReadBuffer(addr, 4);
			if (buf.GetLength() < 4)
			{
				addr += 4;
				continue;
			}
			
			uint32_t value = ReadU32Unaligned(buf.GetData());
			
			// Check if it's a code pointer within this segment
			if (value < seg->GetStart() || value >= seg->GetEnd())
			{
				addr += 4;
				continue;
			}
			
			// Potential jump table
			DetectedStructure jt;
			jt.address = addr;
			jt.type = StructureType::JumpTable;
			jt.elementSize = 4;
			
			uint64_t scanAddr = addr;
			while (scanAddr + 4 <= seg->GetEnd() && jt.elements.size() < settings.maxElements)
			{
				buf = m_view->ReadBuffer(scanAddr, 4);
				if (buf.GetLength() < 4)
					break;
				
				uint32_t ptr = ReadU32Unaligned(buf.GetData());
				
				// Must be within same segment and look like code
				if (ptr < seg->GetStart() || ptr >= seg->GetEnd())
					break;
				
				// Should be aligned
				if (ptr & 1)
					ptr &= ~1ULL;  // Thumb
				else if (ptr & 3)
					break;  // Misaligned
				
				jt.elements.push_back(ptr);
				jt.functionTargets.push_back(ptr);
				jt.elementNames.push_back(resolveSymbol(ptr));
				
				scanAddr += 4;
			}
			
			if (jt.elements.size() >= settings.minElements)
			{
				jt.elementCount = jt.elements.size();
				jt.size = jt.elementCount * 4;
				jt.description = "Switch/case jump table";
				jt.isNew = true;
				
				auto refs = m_view->GetCodeReferences(addr);
				for (const auto& ref : refs)
					jt.xrefSources.push_back(ref.addr);
				
				jt.confidence = calculateConfidence(jt, settings);
				jt.inferredTypeName = "jumptable_" + std::to_string(addr);
				
				if (jt.confidence >= settings.minConfidence)
				{
					results.push_back(jt);
					m_stats.jumpTables++;
				}
				
				addr = scanAddr;
			}
			else
			{
				addr += 4;
			}
		}
	}
}

void StructureDetector::scanForFunctionTables(const StructureDetectionSettings& settings, std::vector<DetectedStructure>& results)
{
	// Function tables are arrays of function pointers in data sections
	// Different from vtables in that they might have gaps or be interrupt handlers
	
	for (const auto& seg : m_view->GetSegments())
	{
		if (seg->GetFlags() & SegmentExecutable)
			continue;
		if (!(seg->GetFlags() & SegmentReadable))
			continue;
		
		uint64_t addr = seg->GetStart();
		addr = (addr + 3) & ~3ULL;
		
		while (addr + 4 <= seg->GetEnd())
		{
			DataBuffer buf = m_view->ReadBuffer(addr, 4);
			if (buf.GetLength() < 4)
			{
				addr += 4;
				continue;
			}
			
			uint32_t value = ReadU32Unaligned(buf.GetData());
			
			// Could be null (unused handler slot) or code pointer
			if (value != 0 && !isCodePointer(value))
			{
				addr += 4;
				continue;
			}
			
			DetectedStructure ft;
			ft.address = addr;
			ft.type = StructureType::FunctionTable;
			ft.elementSize = 4;
			
			size_t nullCount = 0;
			uint64_t scanAddr = addr;
			
			while (scanAddr + 4 <= seg->GetEnd() && ft.elements.size() < settings.maxElements)
			{
				buf = m_view->ReadBuffer(scanAddr, 4);
				if (buf.GetLength() < 4)
					break;
				
				uint32_t ptr = ReadU32Unaligned(buf.GetData());
				
				if (ptr == 0)
				{
					nullCount++;
					if (nullCount > 2)  // Too many nulls - probably end of table
						break;
					ft.elements.push_back(0);
					ft.functionTargets.push_back(0);
					ft.elementNames.push_back("(null)");
				}
				else if (isCodePointer(ptr))
				{
					nullCount = 0;
					ft.elements.push_back(ptr);
					ft.functionTargets.push_back(ptr & ~1ULL);
					ft.elementNames.push_back(resolveSymbol(ptr & ~1ULL));
				}
				else
				{
					break;  // Not a valid entry
				}
				
				scanAddr += 4;
			}
			
			// Filter out trailing nulls
			while (!ft.elements.empty() && ft.elements.back() == 0)
			{
				ft.elements.pop_back();
				ft.functionTargets.pop_back();
				ft.elementNames.pop_back();
			}
			
			if (ft.elements.size() >= settings.minElements)
			{
				// Check if it's actually a vtable (no nulls, all named)
				bool hasNulls = false;
				for (auto e : ft.elements)
					if (e == 0) { hasNulls = true; break; }
				
				if (!hasNulls && results.size() > 0)
				{
					// Skip - probably detected as vtable
					addr = scanAddr;
					continue;
				}
				
				ft.elementCount = ft.elements.size();
				ft.size = ft.elementCount * 4;
				ft.description = hasNulls ? "Handler/callback table (sparse)" : "Function pointer array";
				ft.isNew = true;
				
				auto refs = m_view->GetCodeReferences(addr);
				for (const auto& ref : refs)
					ft.xrefSources.push_back(ref.addr);
				
				ft.confidence = calculateConfidence(ft, settings);
				ft.inferredTypeName = "func_table_" + std::to_string(addr);
				
				if (ft.confidence >= settings.minConfidence)
				{
					results.push_back(ft);
					m_stats.functionTables++;
					
					// Count non-null functions discovered
					for (auto ptr : ft.functionTargets)
						if (ptr != 0) m_stats.totalFunctionsDiscovered++;
				}
				
				addr = scanAddr;
			}
			else
			{
				addr += 4;
			}
		}
	}
}

void StructureDetector::scanForPointerArrays(const StructureDetectionSettings& settings, std::vector<DetectedStructure>& results)
{
	// Look for arrays of data pointers
	for (const auto& seg : m_view->GetSegments())
	{
		if (seg->GetFlags() & SegmentExecutable)
			continue;
		if (!(seg->GetFlags() & SegmentReadable))
			continue;
		
		uint64_t addr = seg->GetStart();
		addr = (addr + 3) & ~3ULL;
		
		while (addr + 4 <= seg->GetEnd())
		{
			DataBuffer buf = m_view->ReadBuffer(addr, 4);
			if (buf.GetLength() < 4)
			{
				addr += 4;
				continue;
			}
			
			uint32_t value = ReadU32Unaligned(buf.GetData());
			
			if (!isDataPointer(value))
			{
				addr += 4;
				continue;
			}
			
			DetectedStructure pa;
			pa.address = addr;
			pa.type = StructureType::PointerArray;
			pa.elementSize = 4;
			
			uint64_t scanAddr = addr;
			bool allStrings = true;
			
			while (scanAddr + 4 <= seg->GetEnd() && pa.elements.size() < settings.maxElements)
			{
				buf = m_view->ReadBuffer(scanAddr, 4);
				if (buf.GetLength() < 4)
					break;
				
				uint32_t ptr = ReadU32Unaligned(buf.GetData());
				
				if (!isDataPointer(ptr))
					break;
				
				pa.elements.push_back(ptr);
				
				// Check if target is a string by looking at the data
				bool isString = false;
				DataBuffer strBuf = m_view->ReadBuffer(ptr, 64);
				if (strBuf.GetLength() > 0)
				{
					const uint8_t* strData = static_cast<const uint8_t*>(strBuf.GetData());
					// Simple check: starts with printable ASCII
					if (strData[0] >= 0x20 && strData[0] < 0x7F)
					{
						std::string preview;
						for (size_t j = 0; j < strBuf.GetLength() && strData[j] != 0 && j < 32; j++)
						{
							if (strData[j] >= 0x20 && strData[j] < 0x7F)
								preview += static_cast<char>(strData[j]);
							else
								break;
						}
						if (preview.length() >= 4)
						{
							pa.elementNames.push_back(preview);
							isString = true;
						}
					}
				}
				if (!isString)
				{
					pa.elementNames.push_back("");
					allStrings = false;
				}
				
				scanAddr += 4;
			}
			
			if (pa.elements.size() >= settings.minElements)
			{
				pa.elementCount = pa.elements.size();
				pa.size = pa.elementCount * 4;
				
				if (allStrings)
				{
					pa.type = StructureType::StringTable;
					pa.description = "String pointer table";
				}
				else
				{
					pa.description = "Data pointer array";
				}
				
				pa.isNew = true;
				pa.confidence = calculateConfidence(pa, settings);
				pa.inferredTypeName = allStrings ? "string_table_" : "ptr_array_";
				pa.inferredTypeName += std::to_string(addr);
				
				if (pa.confidence >= settings.minConfidence)
				{
					results.push_back(pa);
					m_stats.pointerArrays++;
				}
				
				addr = scanAddr;
			}
			else
			{
				addr += 4;
			}
		}
	}
}

void StructureDetector::scanForIntegerArrays(const StructureDetectionSettings& settings, std::vector<DetectedStructure>& results)
{
	// Look for arrays of similar integers (not pointers)
	// This is more heuristic - we look for runs of similar-magnitude values
	
	for (const auto& seg : m_view->GetSegments())
	{
		if (seg->GetFlags() & SegmentExecutable)
			continue;
		if (!(seg->GetFlags() & SegmentReadable))
			continue;
		
		uint64_t addr = seg->GetStart();
		addr = (addr + 3) & ~3ULL;
		
		while (addr + 4 <= seg->GetEnd())
		{
			DataBuffer buf = m_view->ReadBuffer(addr, 4);
			if (buf.GetLength() < 4)
			{
				addr += 4;
				continue;
			}
			
			uint32_t value = ReadU32Unaligned(buf.GetData());
			
			// Skip if it looks like a pointer
			if (isValidPointer(value))
			{
				addr += 4;
				continue;
			}
			
			// Skip null/common values
			if (value == 0 || value == 0xFFFFFFFF)
			{
				addr += 4;
				continue;
			}
			
			// Look for similar values
			DetectedStructure ia;
			ia.address = addr;
			ia.type = StructureType::IntegerArray;
			ia.elementSize = 4;
			
			uint64_t scanAddr = addr;
			uint32_t minVal = value, maxVal = value;
			
			while (scanAddr + 4 <= seg->GetEnd() && ia.elements.size() < settings.maxElements)
			{
				buf = m_view->ReadBuffer(scanAddr, 4);
				if (buf.GetLength() < 4)
					break;
				
				uint32_t v = ReadU32Unaligned(buf.GetData());
				
				// Skip pointers
				if (isValidPointer(v))
					break;
				
				// Check if value is in reasonable range of existing values
				// Allow sparse data (0 is ok, 0xFFFFFFFF is ok)
				if (v != 0 && v != 0xFFFFFFFF)
				{
					if (v < minVal) minVal = v;
					if (v > maxVal) maxVal = v;
					
					// If range gets too large, probably not a uniform array
					if (maxVal > 0 && minVal > 0 && maxVal / minVal > 1000)
						break;
				}
				
				ia.elements.push_back(v);
				scanAddr += 4;
			}
			
			if (ia.elements.size() >= settings.minElements)
			{
				ia.elementCount = ia.elements.size();
				ia.size = ia.elementCount * 4;
				ia.description = "Integer array";
				ia.isNew = true;
				ia.confidence = calculateConfidence(ia, settings) - 0.1;  // Lower confidence for integers
				ia.inferredTypeName = "int_array_" + std::to_string(addr);
				
				if (ia.confidence >= settings.minConfidence)
				{
					results.push_back(ia);
					m_stats.integerArrays++;
				}
				
				addr = scanAddr;
			}
			else
			{
				addr += 4;
			}
		}
	}
}

std::vector<DetectedStructure> StructureDetector::Detect(const StructureDetectionSettings& settings)
{
	std::vector<DetectedStructure> results;
	
	m_stats = {};
	
	if (settings.detectVtables)
		scanForVtables(settings, results);
	
	if (settings.detectJumpTables)
		scanForJumpTables(settings, results);
	
	if (settings.detectFunctionTables)
		scanForFunctionTables(settings, results);
	
	if (settings.detectPointerArrays)
		scanForPointerArrays(settings, results);
	
	if (settings.detectIntegerArrays)
		scanForIntegerArrays(settings, results);
	
	// Sort by address and remove overlaps
	std::sort(results.begin(), results.end(), [](const DetectedStructure& a, const DetectedStructure& b) {
		return a.address < b.address;
	});
	
	// Remove overlapping structures, keeping higher confidence
	std::vector<DetectedStructure> deduped;
	for (const auto& s : results)
	{
		bool overlaps = false;
		for (auto& existing : deduped)
		{
			if (s.address < existing.address + existing.size && 
				s.address + s.size > existing.address)
			{
				overlaps = true;
				if (s.confidence > existing.confidence)
					existing = s;
				break;
			}
		}
		if (!overlaps)
			deduped.push_back(s);
	}
	
	m_stats.totalFound = deduped.size();
	m_stats.newStructures = deduped.size();  // TODO: track existing
	
	return deduped;
}

}
