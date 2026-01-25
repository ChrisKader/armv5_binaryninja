/*
 * ARMv5 Relocations
 */

#include "relocations/relocations.h"

#include <inttypes.h>
#include <map>
#include <set>
#include <vector>

using namespace BinaryNinja;

static Ref<Logger> GetRelocLogger()
{
	static Ref<Logger> logger = LogRegistry::CreateLogger("ARMv5.Relocations");
	return logger;
}

static const char* GetRelocationString(ElfArmRelocationType rel)
{
	static std::map<ElfArmRelocationType, const char*> relocTable =
		{
			{R_ARM_NONE, "R_ARM_NONE"},
			{R_ARM_PC24, "R_ARM_PC24"},
			{R_ARM_ABS32, "R_ARM_ABS32"},
			{R_ARM_REL32, "R_ARM_REL32"},
			{R_ARM_LDR_PC_G0, "R_ARM_LDR_PC_G0"},
			{R_ARM_ABS16, "R_ARM_ABS16"},
			{R_ARM_ABS12, "R_ARM_ABS12"},
			{R_ARM_THM_ABS5, "R_ARM_THM_ABS5"},
			{R_ARM_ABS8, "R_ARM_ABS8"},
			{R_ARM_SBREL32, "R_ARM_SBREL32"},
			{R_ARM_THM_CALL, "R_ARM_THM_CALL"},
			{R_ARM_THM_PC8, "R_ARM_THM_PC8"},
			{R_ARM_BREL_ADJ, "R_ARM_BREL_ADJ"},
			{R_ARM_TLS_DESC, "R_ARM_TLS_DESC"},
			{R_ARM_THM_SWI8, "R_ARM_THM_SWI8"},
			{R_ARM_XPC25, "R_ARM_XPC25"},
			{R_ARM_THM_XPC22, "R_ARM_THM_XPC22"},
			{R_ARM_TLS_DTPMOD32, "R_ARM_TLS_DTPMOD32"},
			{R_ARM_TLS_DTPOFF32, "R_ARM_TLS_DTPOFF32"},
			{R_ARM_TLS_TPOFF32, "R_ARM_TLS_TPOFF32"},
			{R_ARM_COPY, "R_ARM_COPY"},
			{R_ARM_GLOB_DAT, "R_ARM_GLOB_DAT"},
			{R_ARM_JUMP_SLOT, "R_ARM_JUMP_SLOT"},
			{R_ARM_RELATIVE, "R_ARM_RELATIVE"},
			{R_ARM_GOTOFF32, "R_ARM_GOTOFF32"},
			{R_ARM_BASE_PREL, "R_ARM_BASE_PREL"},
			{R_ARM_GOT_BREL, "R_ARM_GOT_BREL"},
			{R_ARM_PLT32, "R_ARM_PLT32"},
			{R_ARM_CALL, "R_ARM_CALL"},
			{R_ARM_JUMP24, "R_ARM_JUMP24"},
			{R_ARM_THM_JUMP24, "R_ARM_THM_JUMP24"},
			{R_ARM_BASE_ABS, "R_ARM_BASE_ABS"},
			{R_ARM_ALU_PCREL_7_0, "R_ARM_ALU_PCREL_7_0"},
			{R_ARM_ALU_PCREL_15_8, "R_ARM_ALU_PCREL_15_8"},
			{R_ARM_ALU_PCREL_23_15, "R_ARM_ALU_PCREL_23_15"},
			{R_ARM_LDR_SBREL_11_0_NC, "R_ARM_LDR_SBREL_11_0_NC"},
			{R_ARM_ALU_SBREL_19_12_NC, "R_ARM_ALU_SBREL_19_12_NC"},
			{R_ARM_ALU_SBREL_27_20_CK, "R_ARM_ALU_SBREL_27_20_CK"},
			{R_ARM_TARGET1, "R_ARM_TARGET1"},
			{R_ARM_SBREL31, "R_ARM_SBREL31"},
			{R_ARM_V4BX, "R_ARM_V4BX"},
			{R_ARM_TARGET2, "R_ARM_TARGET2"},
			{R_ARM_PREL31, "R_ARM_PREL31"},
			{R_ARM_MOVW_ABS_NC, "R_ARM_MOVW_ABS_NC"},
			{R_ARM_MOVT_ABS, "R_ARM_MOVT_ABS"},
			{R_ARM_MOVW_PREL_NC, "R_ARM_MOVW_PREL_NC"},
			{R_ARM_MOVT_PREL, "R_ARM_MOVT_PREL"},
			{R_ARM_THM_MOVW_ABS_NC, "R_ARM_THM_MOVW_ABS_NC"},
			{R_ARM_THM_MOVT_ABS, "R_ARM_THM_MOVT_ABS"},
			{R_ARM_THM_MOVW_PREL_NC, "R_ARM_THM_MOVW_PREL_NC"},
			{R_ARM_THM_MOVT_PREL, "R_ARM_THM_MOVT_PREL"},
			{R_ARM_THM_JUMP19, "R_ARM_THM_JUMP19"},
			{R_ARM_THM_JUMP6, "R_ARM_THM_JUMP6"},
			{R_ARM_THM_ALU_PREL_11_0, "R_ARM_THM_ALU_PREL_11_0"},
			{R_ARM_THM_PC12, "R_ARM_THM_PC12"},
			{R_ARM_ABS32_NOI, "R_ARM_ABS32_NOI"},
			{R_ARM_REL32_NOI, "R_ARM_REL32_NOI"},
			{R_ARM_ALU_PC_G0_NC, "R_ARM_ALU_PC_G0_NC"},
			{R_ARM_ALU_PC_G0, "R_ARM_ALU_PC_G0"},
			{R_ARM_ALU_PC_G1_NC, "R_ARM_ALU_PC_G1_NC"},
			{R_ARM_ALU_PC_G1, "R_ARM_ALU_PC_G1"},
			{R_ARM_ALU_PC_G2, "R_ARM_ALU_PC_G2"},
			{R_ARM_LDR_PC_G1, "R_ARM_LDR_PC_G1"},
			{R_ARM_LDR_PC_G2, "R_ARM_LDR_PC_G2"},
			{R_ARM_LDRS_PC_G0, "R_ARM_LDRS_PC_G0"},
			{R_ARM_LDRS_PC_G1, "R_ARM_LDRS_PC_G1"},
			{R_ARM_LDRS_PC_G2, "R_ARM_LDRS_PC_G2"},
			{R_ARM_LDC_PC_G0, "R_ARM_LDC_PC_G0"},
			{R_ARM_LDC_PC_G1, "R_ARM_LDC_PC_G1"},
			{R_ARM_LDC_PC_G2, "R_ARM_LDC_PC_G2"},
			{R_ARM_ALU_SB_G0_NC, "R_ARM_ALU_SB_G0_NC"},
			{R_ARM_ALU_SB_G0, "R_ARM_ALU_SB_G0"},
			{R_ARM_ALU_SB_G1_NC, "R_ARM_ALU_SB_G1_NC"},
			{R_ARM_ALU_SB_G1, "R_ARM_ALU_SB_G1"},
			{R_ARM_ALU_SB_G2, "R_ARM_ALU_SB_G2"},
			{R_ARM_LDR_SB_G0, "R_ARM_LDR_SB_G0"},
			{R_ARM_LDR_SB_G1, "R_ARM_LDR_SB_G1"},
			{R_ARM_LDR_SB_G2, "R_ARM_LDR_SB_G2"},
			{R_ARM_LDRS_SB_G0, "R_ARM_LDRS_SB_G0"},
			{R_ARM_LDRS_SB_G1, "R_ARM_LDRS_SB_G1"},
			{R_ARM_LDRS_SB_G2, "R_ARM_LDRS_SB_G2"},
			{R_ARM_LDC_SB_G0, "R_ARM_LDC_SB_G0"},
			{R_ARM_LDC_SB_G1, "R_ARM_LDC_SB_G1"},
			{R_ARM_LDC_SB_G2, "R_ARM_LDC_SB_G2"},
			{R_ARM_MOVW_BREL_NC, "R_ARM_MOVW_BREL_NC"},
			{R_ARM_MOVT_BREL, "R_ARM_MOVT_BREL"},
			{R_ARM_MOVW_BREL, "R_ARM_MOVW_BREL"},
			{R_ARM_THM_MOVW_BREL_NC, "R_ARM_THM_MOVW_BREL_NC"},
			{R_ARM_THM_MOVT_BREL, "R_ARM_THM_MOVT_BREL"},
			{R_ARM_THM_MOVW_BREL, "R_ARM_THM_MOVW_BREL"},
			{R_ARM_TLS_GOTDESC, "R_ARM_TLS_GOTDESC"},
			{R_ARM_TLS_CALL, "R_ARM_TLS_CALL"},
			{R_ARM_TLS_DESCSEQ, "R_ARM_TLS_DESCSEQ"},
			{R_ARM_THM_TLS_CALL, "R_ARM_THM_TLS_CALL"},
			{R_ARM_PLT32_ABS, "R_ARM_PLT32_ABS"},
			{R_ARM_GOT_ABS, "R_ARM_GOT_ABS"},
			{R_ARM_GOT_PREL, "R_ARM_GOT_PREL"},
			{R_ARM_GOT_BREL12, "R_ARM_GOT_BREL12"},
			{R_ARM_GOTOFF12, "R_ARM_GOTOFF12"},
			{R_ARM_GOTRELAX, "R_ARM_GOTRELAX"},
			{R_ARM_GNU_VTENTRY, "R_ARM_GNU_VTENTRY"},
			{R_ARM_GNU_VTINHERIT, "R_ARM_GNU_VTINHERIT"},
			{R_ARM_THM_JUMP11, "R_ARM_THM_JUMP11"},
			{R_ARM_THM_JUMP8, "R_ARM_THM_JUMP8"},
			{R_ARM_TLS_GD32, "R_ARM_TLS_GD32"},
			{R_ARM_TLS_LDM32, "R_ARM_TLS_LDM32"},
			{R_ARM_TLS_LDO32, "R_ARM_TLS_LDO32"},
			{R_ARM_TLS_IE32, "R_ARM_TLS_IE32"},
			{R_ARM_TLS_LE32, "R_ARM_TLS_LE32"},
			{R_ARM_TLS_LDO12, "R_ARM_TLS_LDO12"},
			{R_ARM_TLS_LE12, "R_ARM_TLS_LE12"},
			{R_ARM_TLS_IE12GP, "R_ARM_TLS_IE12GP"},
			{R_ARM_PRIVATE_0, "R_ARM_PRIVATE_0"},
			{R_ARM_PRIVATE_1, "R_ARM_PRIVATE_1"},
			{R_ARM_PRIVATE_2, "R_ARM_PRIVATE_2"},
			{R_ARM_PRIVATE_3, "R_ARM_PRIVATE_3"},
			{R_ARM_PRIVATE_4, "R_ARM_PRIVATE_4"},
			{R_ARM_PRIVATE_5, "R_ARM_PRIVATE_5"},
			{R_ARM_PRIVATE_6, "R_ARM_PRIVATE_6"},
			{R_ARM_PRIVATE_7, "R_ARM_PRIVATE_7"},
			{R_ARM_PRIVATE_8, "R_ARM_PRIVATE_8"},
			{R_ARM_PRIVATE_9, "R_ARM_PRIVATE_9"},
			{R_ARM_PRIVATE_10, "R_ARM_PRIVATE_10"},
			{R_ARM_PRIVATE_11, "R_ARM_PRIVATE_11"},
			{R_ARM_PRIVATE_12, "R_ARM_PRIVATE_12"},
			{R_ARM_PRIVATE_13, "R_ARM_PRIVATE_13"},
			{R_ARM_PRIVATE_14, "R_ARM_PRIVATE_14"},
			{R_ARM_PRIVATE_15, "R_ARM_PRIVATE_15"},
			{R_ARM_ME_TOO, "R_ARM_ME_TOO"},
			{R_ARM_THM_TLS_DESCSEQ16, "R_ARM_THM_TLS_DESCSEQ16"},
			{R_ARM_THM_TLS_DESCSEQ32, "R_ARM_THM_TLS_DESCSEQ32"},
			{R_ARM_THM_GOT_BREL12, "R_ARM_THM_GOT_BREL12"},
			{R_ARM_THM_ALU_ABS_G0_NC, "R_ARM_THM_ALU_ABS_G0_NC"},
			{R_ARM_THM_ALU_ABS_G1_NC, "R_ARM_THM_ALU_ABS_G1_NC"},
			{R_ARM_THM_ALU_ABS_G2_NC, "R_ARM_THM_ALU_ABS_G2_NC"},
			{R_ARM_THM_ALU_ABS_G3, "R_ARM_THM_ALU_ABS_G3"},
			{R_ARM_IRELATIVE, "R_ARM_IRELATIVE"},
			{R_ARM_RXPC25, "R_ARM_RXPC25"},
			{R_ARM_RSBREL32, "R_ARM_RSBREL32"},
			{R_ARM_THM_RPC22, "R_ARM_THM_RPC22"},
			{R_ARM_RREL32, "R_ARM_RREL32"},
			{R_ARM_RABS32, "R_ARM_RABS32"},
			{R_ARM_RPC24, "R_ARM_RPC24"},
			{R_ARM_RBASE, "R_ARM_RBASE"}};
	auto it = relocTable.find(rel);
	if (it != relocTable.end())
		return it->second;
	return "Unknown ARM relocation";
}

static bool IsELFDataRelocation(ElfArmRelocationType reloc)
{
	static std::map<ElfArmRelocationType, bool> isDataMap =
		{
			{R_ARM_NONE, false},
			{R_ARM_PC24, false},
			{R_ARM_ABS32, true},
			{R_ARM_REL32, true},
			{R_ARM_LDR_PC_G0, false},
			{R_ARM_ABS16, true},
			{R_ARM_ABS12, false},
			{R_ARM_THM_ABS5, false},
			{R_ARM_ABS8, true},
			{R_ARM_SBREL32, true},
			{R_ARM_THM_CALL, false},
			{R_ARM_THM_PC8, false},
			{R_ARM_BREL_ADJ, true},
			{R_ARM_TLS_DESC, true},
			{R_ARM_THM_SWI8, false},
			{R_ARM_XPC25, false},
			{R_ARM_THM_XPC22, false},
			{R_ARM_TLS_DTPMOD32, true},
			{R_ARM_TLS_DTPOFF32, true},
			{R_ARM_TLS_TPOFF32, true},
			{R_ARM_COPY, true},
			{R_ARM_GLOB_DAT, true},
			{R_ARM_JUMP_SLOT, true},
			{R_ARM_RELATIVE, true},
			{R_ARM_GOTOFF32, true},
			{R_ARM_BASE_PREL, true},
			{R_ARM_GOT_BREL, true},
			{R_ARM_PLT32, false},
			{R_ARM_CALL, false},
			{R_ARM_JUMP24, false},
			{R_ARM_THM_JUMP24, false},
			{R_ARM_BASE_ABS, true},
			{R_ARM_ALU_PCREL_7_0, false},
			{R_ARM_ALU_PCREL_15_8, false},
			{R_ARM_ALU_PCREL_23_15, false},
			{R_ARM_LDR_SBREL_11_0_NC, false},
			{R_ARM_ALU_SBREL_19_12_NC, false},
			{R_ARM_ALU_SBREL_27_20_CK, false},
			{R_ARM_TARGET1, false},
			{R_ARM_SBREL31, true},
			{R_ARM_V4BX, false},
			{R_ARM_TARGET2, false},
			{R_ARM_PREL31, true},
			{R_ARM_MOVW_ABS_NC, false},
			{R_ARM_MOVT_ABS, false},
			{R_ARM_MOVW_PREL_NC, false},
			{R_ARM_MOVT_PREL, false},
			{R_ARM_THM_MOVW_ABS_NC, false},
			{R_ARM_THM_MOVT_ABS, false},
			{R_ARM_THM_MOVW_PREL_NC, false},
			{R_ARM_THM_MOVT_PREL, false},
			{R_ARM_THM_JUMP19, false},
			{R_ARM_THM_JUMP6, false},
			{R_ARM_THM_ALU_PREL_11_0, false},
			{R_ARM_THM_PC12, false},
			{R_ARM_ABS32_NOI, true},
			{R_ARM_REL32_NOI, true},
			{R_ARM_ALU_PC_G0_NC, false},
			{R_ARM_ALU_PC_G0, false},
			{R_ARM_ALU_PC_G1_NC, false},
			{R_ARM_ALU_PC_G1, false},
			{R_ARM_ALU_PC_G2, false},
			{R_ARM_LDR_PC_G1, false},
			{R_ARM_LDR_PC_G2, false},
			{R_ARM_LDRS_PC_G0, false},
			{R_ARM_LDRS_PC_G1, false},
			{R_ARM_LDRS_PC_G2, false},
			{R_ARM_LDC_PC_G0, false},
			{R_ARM_LDC_PC_G1, false},
			{R_ARM_LDC_PC_G2, false},
			{R_ARM_ALU_SB_G0_NC, false},
			{R_ARM_ALU_SB_G0, false},
			{R_ARM_ALU_SB_G1_NC, false},
			{R_ARM_ALU_SB_G1, false},
			{R_ARM_ALU_SB_G2, false},
			{R_ARM_LDR_SB_G0, false},
			{R_ARM_LDR_SB_G1, false},
			{R_ARM_LDR_SB_G2, false},
			{R_ARM_LDRS_SB_G0, false},
			{R_ARM_LDRS_SB_G1, false},
			{R_ARM_LDRS_SB_G2, false},
			{R_ARM_LDC_SB_G0, false},
			{R_ARM_LDC_SB_G1, false},
			{R_ARM_LDC_SB_G2, false},
			{R_ARM_MOVW_BREL_NC, false},
			{R_ARM_MOVT_BREL, false},
			{R_ARM_MOVW_BREL, false},
			{R_ARM_THM_MOVW_BREL_NC, false},
			{R_ARM_THM_MOVT_BREL, false},
			{R_ARM_THM_MOVW_BREL, false},
			{R_ARM_TLS_GOTDESC, true},
			{R_ARM_TLS_CALL, false},
			{R_ARM_TLS_DESCSEQ, true},
			{R_ARM_THM_TLS_CALL, false},
			{R_ARM_PLT32_ABS, true},
			{R_ARM_GOT_ABS, true},
			{R_ARM_GOT_PREL, true},
			{R_ARM_GOT_BREL12, true},
			{R_ARM_GOTOFF12, true},
			{R_ARM_GOTRELAX, true},
			{R_ARM_GNU_VTENTRY, true},
			{R_ARM_GNU_VTINHERIT, true},
			{R_ARM_THM_JUMP11, false},
			{R_ARM_THM_JUMP8, false},
			{R_ARM_TLS_GD32, true},
			{R_ARM_TLS_LDM32, true},
			{R_ARM_TLS_LDO32, true},
			{R_ARM_TLS_IE32, true},
			{R_ARM_TLS_LE32, true},
			{R_ARM_TLS_LDO12, true},
			{R_ARM_TLS_LE12, true},
			{R_ARM_TLS_IE12GP, true},
			{R_ARM_PRIVATE_0, true},
			{R_ARM_PRIVATE_1, true},
			{R_ARM_PRIVATE_2, true},
			{R_ARM_PRIVATE_3, true},
			{R_ARM_PRIVATE_4, true},
			{R_ARM_PRIVATE_5, true},
			{R_ARM_PRIVATE_6, true},
			{R_ARM_PRIVATE_7, true},
			{R_ARM_PRIVATE_8, true},
			{R_ARM_PRIVATE_9, true},
			{R_ARM_PRIVATE_10, true},
			{R_ARM_PRIVATE_11, true},
			{R_ARM_PRIVATE_12, true},
			{R_ARM_PRIVATE_13, true},
			{R_ARM_PRIVATE_14, true},
			{R_ARM_PRIVATE_15, true},
			{R_ARM_ME_TOO, true},
			{R_ARM_THM_TLS_DESCSEQ16, true},
			{R_ARM_THM_TLS_DESCSEQ32, true},
			{R_ARM_THM_GOT_BREL12, true},
			{R_ARM_THM_ALU_ABS_G0_NC, false},
			{R_ARM_THM_ALU_ABS_G1_NC, false},
			{R_ARM_THM_ALU_ABS_G2_NC, false},
			{R_ARM_THM_ALU_ABS_G3, false},
			{R_ARM_IRELATIVE, true},
			{R_ARM_RXPC25, false},
			{R_ARM_RSBREL32, true},
			{R_ARM_THM_RPC22, false},
			{R_ARM_RREL32, true},
			{R_ARM_RABS32, true},
			{R_ARM_RPC24, false},
			{R_ARM_RBASE, true}};
	auto it = isDataMap.find(reloc);
	if (it == isDataMap.end())
		return false;
	return it->second;
}

/*
 * Byte swap helper for big endian support
 */
static uint32_t bswap32(uint32_t x)
{
	return ((x & 0xff000000) >> 24) |
		((x & 0x00ff0000) >> 8) |
		((x & 0x0000ff00) << 8) |
		((x & 0x000000ff) << 24);
}

/*
 * ELF Relocation Handler for ARMv5
 */
class Armv5ElfRelocationHandler : public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc,
		uint8_t* dest, size_t len) override
	{
		(void)view;
		BNRelocationInfo info = reloc->GetInfo();
		if (len < info.size)
			return false;
		Ref<Symbol> sym = reloc->GetSymbol();
		uint32_t target = (uint32_t)reloc->GetTarget();
		uint32_t* dest32 = (uint32_t*)dest;

		auto swap = [&arch](uint32_t x)
		{ return (arch->GetEndianness() == LittleEndian) ? x : bswap32(x); };
		switch (info.nativeType)
		{
		case R_ARM_COPY:
		case R_ARM_GLOB_DAT:
		case R_ARM_JUMP_SLOT:
		case R_ARM_BASE_PREL:
		case R_ARM_GOT_BREL:
			dest32[0] = swap(target);
			break;
		case R_ARM_RELATIVE:
		case R_ARM_ABS32:
			dest32[0] = swap(swap(dest32[0]) + target);
			break;
		case R_ARM_REL32:
			dest32[0] = swap((uint32_t)((target + (info.implicitAddend ? swap(dest32[0]) : info.addend)) - reloc->GetAddress()));
			break;
		case R_ARM_CALL:
		{
			if (target & 1)
			{
				if (auto rLog = GetRelocLogger()) rLog->LogError("Unsupported relocation R_ARM_CALL to thumb target");
				break;
			}
			struct _bl
			{
				int32_t imm : 24;
				uint32_t group1 : 4;
				uint32_t cond : 4;
			};
			_bl* bl = (_bl*)dest32;
			int64_t newTarget = (target + (info.implicitAddend ? ((bl->imm << 2) + 8) : info.addend)) - reloc->GetAddress();
			if ((newTarget - 8) > 0x3ffffff)
			{
				if (auto rLog = GetRelocLogger()) rLog->LogError("Unsupported relocation R_ARM_CALL @ 0x%" PRIx64 " with target greater than 0x3ffffff: 0x%" PRIx64, reloc->GetAddress(), newTarget - 8);
				break;
			}
			bl->imm = (newTarget - 8) >> 2;
			break;
		}
		case R_ARM_THM_CALL:
		case R_ARM_THM_JUMP24:
		{
#pragma pack(push, 1)
			union _thumb32_bl_hw1
			{
				uint16_t word;
				struct
				{
					uint16_t offHi : 10;
					uint16_t sign : 1;
					uint16_t group : 5;
				};
			};

			union _thumb32_bl_hw2
			{
				uint16_t word;
				struct
				{
					uint16_t offLo : 11;
					uint16_t j2 : 1;
					uint16_t thumb : 1;
					uint16_t j1 : 1;
					uint16_t i2 : 1;
					uint16_t i1 : 1;
				};
			};
#pragma pack(pop)

			_thumb32_bl_hw1* bl_hw1 = (_thumb32_bl_hw1*)dest;
			_thumb32_bl_hw2* bl_hw2 = (_thumb32_bl_hw2*)(dest + 2);
			int32_t curTarget = (bl_hw2->offLo << 1) | (bl_hw1->offHi << 12) | (bl_hw1->sign ? (0xffc << 20) : 0);
			int32_t newTarget = (int32_t)((target + (info.implicitAddend ? curTarget : info.addend)) - reloc->GetAddress());

			bl_hw1->sign = newTarget < 0 ? 1 : 0;
			bl_hw1->offHi = newTarget >> 12;
			bl_hw2->offLo = newTarget >> 1;
			break;
		}
		case R_ARM_PREL31:
		{
			dest32[0] = (info.implicitAddend ? dest32[0] : (uint32_t)info.addend) + (target & ~1) - (uint32_t)reloc->GetAddress();
			break;
		}
		case R_ARM_PC24:
		case R_ARM_JUMP24:
		{
			if (target & 1)
			{
				if (auto rLog = GetRelocLogger()) rLog->LogError("Unsupported relocation R_ARM_JUMP24 to thumb target");
				break;
			}
			struct _b
			{
				int32_t imm : 24;
				uint32_t group1 : 4;
				uint32_t cond : 4;
			};
			_b* b = (_b*)dest32;
			int64_t newTarget = (target + (info.implicitAddend ? ((b->imm << 2) + 8) : info.addend)) - reloc->GetAddress();
			if ((newTarget - 8) > 0x3ffffff)
			{
				if (auto rLog = GetRelocLogger()) rLog->LogError("Unsupported relocation R_ARM_JUMP24 0x%" PRIx64 " with target greater than 0x3ffffff: 0x%" PRIx64, reloc->GetAddress(), newTarget - 8);
				break;
			}
			b->imm = (newTarget - 8) >> 2;
			break;
		}
		case R_ARM_MOVW_ABS_NC:
		{
			struct _mov
			{
				uint32_t imm12 : 12;
				uint32_t rd : 4;
				uint32_t imm4 : 4;
				uint32_t group2 : 8;
				uint32_t cond : 4;
			};
			_mov* mov = (_mov*)dest32;
			int64_t newTarget = (target + (info.implicitAddend ? (mov->imm4 << 12 | mov->imm12) : info.addend));
			mov->imm12 = newTarget & 0xfff;
			mov->imm4 = (newTarget >> 12) & 0xf;
			break;
		}
		case R_ARM_MOVT_ABS:
		{
			struct _mov
			{
				uint32_t imm12 : 12;
				uint32_t rd : 4;
				uint32_t imm4 : 4;
				uint32_t group2 : 8;
				uint32_t cond : 4;
			};
			_mov* mov = (_mov*)dest32;
			int64_t newTarget = (target + (info.implicitAddend ? (mov->imm4 << 12 | mov->imm12) : info.addend));
			mov->imm12 = (newTarget >> 16) & 0xfff;
			mov->imm4 = (newTarget >> 28) & 0xf;
			break;
		}
		case R_ARM_THM_MOVW_ABS_NC:
		case R_ARM_THM_MOVT_ABS:
		{
#pragma pack(push, 1)
			struct _mov
			{
				uint32_t imm4 : 4;
				uint32_t group2 : 6;
				uint32_t i : 1;
				uint32_t group3 : 5;
				uint32_t imm8 : 8;
				uint32_t rd : 4;
				uint32_t imm3 : 3;
				uint32_t group1_15 : 1;
			};
			union _target
			{
				struct
				{
					uint16_t imm8 : 8;
					uint16_t imm3 : 3;
					uint16_t i : 1;
					uint16_t imm4 : 4;
				};
				uint16_t word;
			};
#pragma pack(pop)
			_mov* mov = (_mov*)dest32;
			int16_t addend = mov->imm8 | (mov->imm3 << 8) | (mov->i << (8 + 3)) | (mov->imm4 << (8 + 3 + 1));
			int64_t newTarget = target + addend;
			_target t;
			if (info.nativeType == R_ARM_THM_MOVW_ABS_NC)
			{
				t.word = (newTarget & 0xffff);
			}
			else
			{
				t.word = (newTarget >> 16) & 0xffff;
			}
			mov->imm8 = t.imm8;
			mov->imm3 = t.imm3;
			mov->imm4 = t.imm4;
			mov->i = t.i;
			break;
		}
		case R_ARM_TLS_DTPMOD32:
			dest32[0] = 0;
			break;
		case R_ARM_TLS_DTPOFF32:
		{
			if (sym)
				dest32[0] = sym->GetAddress();
			break;
		}
		default:
			return RelocationHandler::ApplyRelocation(view, arch, reloc, dest, len);
		}
		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch,
		std::vector<BNRelocationInfo>& result) override
	{
		(void)view;
		(void)arch;
		std::set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			reloc.type = StandardRelocationType;
			reloc.size = 4;
			reloc.pcRelative = false;
			reloc.dataRelocation = IsELFDataRelocation((ElfArmRelocationType)reloc.nativeType);
			switch (reloc.nativeType)
			{
			case R_ARM_NONE:
				reloc.type = IgnoredRelocation;
				reloc.pcRelative = true;
				break;
			case R_ARM_PREL31:
			case R_ARM_RELATIVE:
				reloc.pcRelative = true;
				break;
			case R_ARM_ABS32:
			case R_ARM_BASE_PREL:
			case R_ARM_GOT_BREL:
				break;
			case R_ARM_CALL:
			case R_ARM_JUMP24:
			case R_ARM_THM_CALL:
			case R_ARM_THM_JUMP24:
				reloc.pcRelative = true;
				break;
			case R_ARM_COPY:
				reloc.type = ELFCopyRelocationType;
				break;
			case R_ARM_GLOB_DAT:
				reloc.type = ELFGlobalRelocationType;
				break;
			case R_ARM_JUMP_SLOT:
				reloc.type = ELFJumpSlotRelocationType;
				break;
			case R_ARM_THM_MOVW_ABS_NC:
			case R_ARM_THM_MOVT_ABS:
			case R_ARM_MOVW_ABS_NC:
			case R_ARM_MOVT_ABS:
				break;
			case R_ARM_REL32:
				reloc.pcRelative = true;
				break;
			case R_ARM_IRELATIVE:
				reloc.baseRelative = true;
				reloc.type = ELFJumpSlotRelocationType;
				break;
			case R_ARM_TLS_DTPMOD32:
				reloc.symbolIndex = 0;
				break;
			case R_ARM_TLS_DTPOFF32:
				break;
			case R_ARM_PC24:
				reloc.pcRelative = true;
				reloc.baseRelative = false;
				reloc.hasSign = false;
				reloc.size = 3;
				reloc.truncateSize = 3;
				break;
			case R_ARM_V4BX:
				reloc.type = IgnoredRelocation;
				break;
			case R_ARM_SBREL31:
			case R_ARM_LDR_PC_G0:
			case R_ARM_ABS16:
			case R_ARM_ABS12:
			case R_ARM_ABS8:
			case R_ARM_SBREL32:
			case R_ARM_BREL_ADJ:
			case R_ARM_TLS_DESC:
			case R_ARM_XPC25:
			case R_ARM_TLS_TPOFF32:
			case R_ARM_GOTOFF32:
			case R_ARM_PLT32:
			case R_ARM_BASE_ABS:
			case R_ARM_ALU_PCREL_7_0:
			case R_ARM_ALU_PCREL_15_8:
			case R_ARM_ALU_PCREL_23_15:
			case R_ARM_LDR_SBREL_11_0_NC:
			case R_ARM_ALU_SBREL_19_12_NC:
			case R_ARM_ALU_SBREL_27_20_CK:
			case R_ARM_TARGET1:
			case R_ARM_TARGET2:
			case R_ARM_MOVW_PREL_NC:
			case R_ARM_MOVT_PREL:
			case R_ARM_THM_MOVW_PREL_NC:
			case R_ARM_THM_MOVT_PREL:
			case R_ARM_THM_JUMP19:
			case R_ARM_THM_JUMP6:
			case R_ARM_THM_ALU_PREL_11_0:
			case R_ARM_THM_PC12:
			case R_ARM_ABS32_NOI:
			case R_ARM_REL32_NOI:
			case R_ARM_ALU_PC_G0_NC:
			case R_ARM_ALU_PC_G0:
			case R_ARM_ALU_PC_G1_NC:
			case R_ARM_ALU_PC_G1:
			case R_ARM_ALU_PC_G2:
			case R_ARM_LDR_PC_G1:
			case R_ARM_LDR_PC_G2:
			case R_ARM_LDRS_PC_G0:
			case R_ARM_LDRS_PC_G1:
			case R_ARM_LDRS_PC_G2:
			case R_ARM_LDC_PC_G0:
			case R_ARM_LDC_PC_G1:
			case R_ARM_LDC_PC_G2:
			case R_ARM_ALU_SB_G0_NC:
			case R_ARM_ALU_SB_G0:
			case R_ARM_ALU_SB_G1_NC:
			case R_ARM_ALU_SB_G1:
			case R_ARM_ALU_SB_G2:
			case R_ARM_LDR_SB_G0:
			case R_ARM_LDR_SB_G1:
			case R_ARM_LDR_SB_G2:
			case R_ARM_LDRS_SB_G0:
			case R_ARM_LDRS_SB_G1:
			case R_ARM_LDRS_SB_G2:
			case R_ARM_LDC_SB_G0:
			case R_ARM_LDC_SB_G1:
			case R_ARM_LDC_SB_G2:
			case R_ARM_MOVW_BREL_NC:
			case R_ARM_MOVT_BREL:
			case R_ARM_MOVW_BREL:
			case R_ARM_THM_MOVW_BREL_NC:
			case R_ARM_THM_MOVT_BREL:
			case R_ARM_THM_MOVW_BREL:
			case R_ARM_TLS_GOTDESC:
			case R_ARM_TLS_CALL:
			case R_ARM_TLS_DESCSEQ:
			case R_ARM_THM_TLS_CALL:
			case R_ARM_PLT32_ABS:
			case R_ARM_GOT_ABS:
			case R_ARM_GOT_PREL:
			case R_ARM_GOT_BREL12:
			case R_ARM_GOTOFF12:
			case R_ARM_GOTRELAX:
			case R_ARM_GNU_VTENTRY:
			case R_ARM_GNU_VTINHERIT:
			case R_ARM_THM_JUMP11:
			case R_ARM_THM_JUMP8:
			case R_ARM_TLS_GD32:
			case R_ARM_TLS_LDM32:
			case R_ARM_TLS_LDO32:
			case R_ARM_TLS_IE32:
			case R_ARM_TLS_LE32:
			case R_ARM_TLS_LDO12:
			case R_ARM_TLS_LE12:
			case R_ARM_TLS_IE12GP:
			case R_ARM_ME_TOO:
			case R_ARM_RXPC25:
			case R_ARM_RSBREL32:
			case R_ARM_THM_RPC22:
			case R_ARM_RREL32:
			case R_ARM_RABS32:
			case R_ARM_RPC24:
			case R_ARM_RBASE:
			default:
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
				break;
			}
		}
		for (auto& reloc : relocTypes)
			if (auto rLog = GetRelocLogger()) rLog->LogWarn("Unsupported ELF relocation: %s", GetRelocationString((ElfArmRelocationType)reloc));
		return true;
	}
};

void RegisterArmv5ElfRelocationHandlers(const Ref<Architecture>& armv5, const Ref<Architecture>& thumb)
{
	if (armv5)
		armv5->RegisterRelocationHandler("ELF", new Armv5ElfRelocationHandler());
	if (thumb)
		thumb->RegisterRelocationHandler("ELF", new Armv5ElfRelocationHandler());
}
