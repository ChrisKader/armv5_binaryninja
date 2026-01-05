/*
 * ARMv5 Architecture Plugin Implementation
 *
 * Provides Binary Ninja integration for ARMv5T/ARMv5TE processors.
 * Follows the same patterns as the ARMv7 plugin in binaryninja-api/arch/armv7/.
 */

#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <exception>
#include <map>
#include <queue>
#include <set>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "arch_armv5.h"
#include "il.h"
#include "armv5_firmware.h"

using namespace BinaryNinja;
using namespace armv5;
using namespace std;

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif
// We need this
// #define DEBUG_COFF LogDebug

#define DISASM_SUCCESS 0
#define FAILED_TO_DISASSEMBLE_OPERAND 1
#define FAILED_TO_DISASSEMBLE_REGISTER 2

#define COALESCE_MAX_INSTRS 100

#define HANDLE_CASE(orig, opposite) \
  case orig:                        \
  case opposite:                    \
    return (candidate == orig) || (candidate == opposite)

static bool GetNextFunctionAfterAddress(Ref<BinaryView> data, Ref<Platform> platform, uint64_t address, Ref<Function>& nextFunc)
{
  uint64_t nextFuncAddr = data->GetNextFunctionStartAfterAddress(address);
  nextFunc = data->GetAnalysisFunction(platform, nextFuncAddr);
  return nextFunc != nullptr;
}

static bool IsRelatedCondition(Condition orig, Condition candidate)
{
  switch (orig)
  {
    HANDLE_CASE(COND_EQ, COND_NE);
    HANDLE_CASE(COND_CS, COND_CC);
    HANDLE_CASE(COND_MI, COND_PL);
    HANDLE_CASE(COND_VS, COND_VC);
    HANDLE_CASE(COND_HI, COND_LS);
    HANDLE_CASE(COND_GE, COND_LT);
    HANDLE_CASE(COND_GT, COND_LE);
  default:
    return false;
  }
}

/*
 * Check if an instruction can be followed by more coalesced conditional instructions
 * Returns false for branches and instructions writing to PC
 */
static bool CanCoalesceAfterInstruction(Instruction &instr)
{
  switch (instr.operation)
  {
  case ARMV5_BX:
  case ARMV5_B:
    return false;

  case ARMV5_ADC:
  case ARMV5_ADD:
  case ARMV5_AND:
  case ARMV5_BIC:
  case ARMV5_EOR:
  case ARMV5_LDR:
  case ARMV5_MOV:
  case ARMV5_MVN:
  case ARMV5_ORR:
  case ARMV5_RSB:
  case ARMV5_RSC:
  case ARMV5_SUB:
  case ARMV5_SBC:
  case ARMV5_LDRH:
  case ARMV5_LDRB:
  case ARMV5_LDRSH:
  case ARMV5_LDRSB:
  case ARMV5_LDRD:
  case ARMV5_MUL:
  case ARMV5_CLZ:
    if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
      return false;
    return true;

  default:
    return true;
  }
}

// We ned MachoArmRelocationType, PeArmRelocationType, PeRelocationType

enum ElfArmRelocationType : uint32_t
{
  R_ARM_NONE = 0,
  R_ARM_PC24 = 1,
  R_ARM_ABS32 = 2,
  R_ARM_REL32 = 3,
  R_ARM_LDR_PC_G0 = 4,
  R_ARM_ABS16 = 5,
  R_ARM_ABS12 = 6,
  R_ARM_THM_ABS5 = 7,
  R_ARM_ABS8 = 8,
  R_ARM_SBREL32 = 9,
  R_ARM_THM_CALL = 10,
  R_ARM_THM_PC8 = 11,
  R_ARM_BREL_ADJ = 12,
  R_ARM_TLS_DESC = 13,
  R_ARM_THM_SWI8 = 14,
  R_ARM_XPC25 = 15,
  R_ARM_THM_XPC22 = 16,
  R_ARM_TLS_DTPMOD32 = 17,
  R_ARM_TLS_DTPOFF32 = 18,
  R_ARM_TLS_TPOFF32 = 19,
  R_ARM_COPY = 20,
  R_ARM_GLOB_DAT = 21,
  R_ARM_JUMP_SLOT = 22,
  R_ARM_RELATIVE = 23,
  R_ARM_GOTOFF32 = 24,
  R_ARM_BASE_PREL = 25,
  R_ARM_GOT_BREL = 26,
  R_ARM_PLT32 = 27,
  R_ARM_CALL = 28,
  R_ARM_JUMP24 = 29,
  R_ARM_THM_JUMP24 = 30,
  R_ARM_BASE_ABS = 31,
  R_ARM_ALU_PCREL_7_0 = 32,
  R_ARM_ALU_PCREL_15_8 = 33,
  R_ARM_ALU_PCREL_23_15 = 34,
  R_ARM_LDR_SBREL_11_0_NC = 35,
  R_ARM_ALU_SBREL_19_12_NC = 36,
  R_ARM_ALU_SBREL_27_20_CK = 37,
  R_ARM_TARGET1 = 38,
  R_ARM_SBREL31 = 39,
  R_ARM_V4BX = 40,
  R_ARM_TARGET2 = 41,
  R_ARM_PREL31 = 42,
  R_ARM_MOVW_ABS_NC = 43,
  R_ARM_MOVT_ABS = 44,
  R_ARM_MOVW_PREL_NC = 45,
  R_ARM_MOVT_PREL = 46,
  R_ARM_THM_MOVW_ABS_NC = 47,
  R_ARM_THM_MOVT_ABS = 48,
  R_ARM_THM_MOVW_PREL_NC = 49,
  R_ARM_THM_MOVT_PREL = 50,
  R_ARM_THM_JUMP19 = 51,
  R_ARM_THM_JUMP6 = 52,
  R_ARM_THM_ALU_PREL_11_0 = 53,
  R_ARM_THM_PC12 = 54,
  R_ARM_ABS32_NOI = 55,
  R_ARM_REL32_NOI = 56,
  R_ARM_ALU_PC_G0_NC = 57,
  R_ARM_ALU_PC_G0 = 58,
  R_ARM_ALU_PC_G1_NC = 59,
  R_ARM_ALU_PC_G1 = 60,
  R_ARM_ALU_PC_G2 = 61,
  R_ARM_LDR_PC_G1 = 62,
  R_ARM_LDR_PC_G2 = 63,
  R_ARM_LDRS_PC_G0 = 64,
  R_ARM_LDRS_PC_G1 = 65,
  R_ARM_LDRS_PC_G2 = 66,
  R_ARM_LDC_PC_G0 = 67,
  R_ARM_LDC_PC_G1 = 68,
  R_ARM_LDC_PC_G2 = 69,
  R_ARM_ALU_SB_G0_NC = 70,
  R_ARM_ALU_SB_G0 = 71,
  R_ARM_ALU_SB_G1_NC = 72,
  R_ARM_ALU_SB_G1 = 73,
  R_ARM_ALU_SB_G2 = 74,
  R_ARM_LDR_SB_G0 = 75,
  R_ARM_LDR_SB_G1 = 76,
  R_ARM_LDR_SB_G2 = 77,
  R_ARM_LDRS_SB_G0 = 78,
  R_ARM_LDRS_SB_G1 = 79,
  R_ARM_LDRS_SB_G2 = 80,
  R_ARM_LDC_SB_G0 = 81,
  R_ARM_LDC_SB_G1 = 82,
  R_ARM_LDC_SB_G2 = 83,
  R_ARM_MOVW_BREL_NC = 84,
  R_ARM_MOVT_BREL = 85,
  R_ARM_MOVW_BREL = 86,
  R_ARM_THM_MOVW_BREL_NC = 87,
  R_ARM_THM_MOVT_BREL = 88,
  R_ARM_THM_MOVW_BREL = 89,
  R_ARM_TLS_GOTDESC = 90,
  R_ARM_TLS_CALL = 91,
  R_ARM_TLS_DESCSEQ = 92,
  R_ARM_THM_TLS_CALL = 93,
  R_ARM_PLT32_ABS = 94,
  R_ARM_GOT_ABS = 95,
  R_ARM_GOT_PREL = 96,
  R_ARM_GOT_BREL12 = 97,
  R_ARM_GOTOFF12 = 98,
  R_ARM_GOTRELAX = 99,
  R_ARM_GNU_VTENTRY = 100,
  R_ARM_GNU_VTINHERIT = 101,
  R_ARM_THM_JUMP11 = 102,
  R_ARM_THM_JUMP8 = 103,
  R_ARM_TLS_GD32 = 104,
  R_ARM_TLS_LDM32 = 105,
  R_ARM_TLS_LDO32 = 106,
  R_ARM_TLS_IE32 = 107,
  R_ARM_TLS_LE32 = 108,
  R_ARM_TLS_LDO12 = 109,
  R_ARM_TLS_LE12 = 110,
  R_ARM_TLS_IE12GP = 111,
  R_ARM_PRIVATE_0 = 112,
  R_ARM_PRIVATE_1 = 113,
  R_ARM_PRIVATE_2 = 114,
  R_ARM_PRIVATE_3 = 115,
  R_ARM_PRIVATE_4 = 116,
  R_ARM_PRIVATE_5 = 117,
  R_ARM_PRIVATE_6 = 118,
  R_ARM_PRIVATE_7 = 119,
  R_ARM_PRIVATE_8 = 120,
  R_ARM_PRIVATE_9 = 121,
  R_ARM_PRIVATE_10 = 122,
  R_ARM_PRIVATE_11 = 123,
  R_ARM_PRIVATE_12 = 124,
  R_ARM_PRIVATE_13 = 125,
  R_ARM_PRIVATE_14 = 126,
  R_ARM_PRIVATE_15 = 127,
  R_ARM_ME_TOO = 128,
  R_ARM_THM_TLS_DESCSEQ16 = 129,
  R_ARM_THM_TLS_DESCSEQ32 = 130,
  R_ARM_THM_GOT_BREL12 = 131,
  R_ARM_THM_ALU_ABS_G0_NC = 132,
  R_ARM_THM_ALU_ABS_G1_NC = 133,
  R_ARM_THM_ALU_ABS_G2_NC = 134,
  R_ARM_THM_ALU_ABS_G3 = 135,
  R_ARM_IRELATIVE = 160,
  R_ARM_RXPC25 = 249,
  R_ARM_RSBREL32 = 250,
  R_ARM_THM_RPC22 = 251,
  R_ARM_RREL32 = 252,
  R_ARM_RABS32 = 253,
  R_ARM_RPC24 = 254,
  R_ARM_RBASE = 255
};

static const char *GetRelocationString(ElfArmRelocationType rel)
{
  static map<ElfArmRelocationType, const char *> relocTable =
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

// GetRelocationString for MachoArmRelocationType, PeArmRelocationType, PeRelocationType

/*
 * ARMv5 Calling Convention (AAPCS-like)
 * Standard ARM calling convention used by most ARM compilers.
 */
static bool IsELFDataRelocation(ElfArmRelocationType reloc)
{
  static map<ElfArmRelocationType, bool> isDataMap =
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
          {R_ARM_TLS_DESCSEQ, false},
          {R_ARM_THM_TLS_CALL, false},
          {R_ARM_PLT32_ABS, true},
          {R_ARM_GOT_ABS, true},
          {R_ARM_GOT_PREL, true},
          {R_ARM_GOT_BREL12, false},
          {R_ARM_GOTOFF12, false},
          {R_ARM_GOTRELAX, false},
          {R_ARM_GNU_VTENTRY, true},
          {R_ARM_GNU_VTINHERIT, true},
          {R_ARM_THM_JUMP11, false},
          {R_ARM_THM_JUMP8, false},
          {R_ARM_TLS_GD32, true},
          {R_ARM_TLS_LDM32, true},
          {R_ARM_TLS_LDO32, true},
          {R_ARM_TLS_IE32, true},
          {R_ARM_TLS_LE32, false},
          {R_ARM_TLS_LDO12, false},
          {R_ARM_TLS_LE12, false},
          {R_ARM_TLS_IE12GP, false},
          {R_ARM_ME_TOO, false},
          {R_ARM_THM_TLS_DESCSEQ16, false},
          {R_ARM_THM_TLS_DESCSEQ32, false},
          {R_ARM_THM_GOT_BREL12, false},
          {R_ARM_THM_ALU_ABS_G0_NC, false},
          {R_ARM_THM_ALU_ABS_G1_NC, false},
          {R_ARM_THM_ALU_ABS_G2_NC, false},
          {R_ARM_THM_ALU_ABS_G3, false},
          {R_ARM_IRELATIVE, false},
          {R_ARM_RXPC25, false},
          {R_ARM_RSBREL32, false},
          {R_ARM_THM_RPC22, false},
          {R_ARM_RREL32, false},
          {R_ARM_RABS32, false},
          {R_ARM_RPC24, false},
          {R_ARM_RBASE, false}};
  if (!isDataMap.count(reloc))
    return false;
  return isDataMap.at(reloc);
}

/* Intrinsic names table removed - using switch statement in GetIntrinsicName like ARMv7 */

static BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false)
{
  BNRegisterInfo result;
  result.fullWidthRegister = fullWidthReg;
  result.offset = offset;
  result.size = size;
  result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
  return result;
}

static int GetOperandCount(const Instruction &instr)
{
  for (int i = 0; i < MAX_OPERANDS; i++)
  {
    if (instr.operands[i].cls == NONE)
      return i;
  }
  return MAX_OPERANDS;
}

/*
 * Armv5Architecture class definition with inline implementations (matches ARMv7 pattern)
 */
class Armv5Architecture : public ArmCommonArchitecture
{
protected:
  virtual std::string GetAssemblerTriple() override
  {
    if (m_endian == BigEndian)
      return "armv5eb-none-none";

    return "armv5-none-none";
  }

  virtual bool Disassemble(const uint8_t *data, uint64_t addr, size_t maxLen, Instruction &result)
  {
    (void)addr;
    (void)maxLen;
    memset(&result, 0, sizeof(result));
    if (armv5_decompose(*(uint32_t*)data, &result, (uint32_t)addr, (uint32_t)(m_endian == BigEndian)) != 0)
      return false;
    return true;
  }

  void SetInstructionInfoForInstruction(uint64_t addr, const Instruction &instr, InstructionInfo &result)
  {
    result.length = 4;

    switch (instr.operation)
    {
    case ARMV5_BL:
      if (UNCONDITIONAL(instr.cond) && (instr.operands[0].cls == LABEL))
      {
        result.AddBranch(CallDestination, instr.operands[0].imm, this);
      }
      break;
    case ARMV5_BLX:
      result.archTransitionByTargetAddr = true;
      if(UNCONDITIONAL(instr.cond))
      {
        if (instr.operands[0].cls == LABEL)
        {
          /* BLX with immediate always switches to Thumb */
          result.AddBranch(CallDestination, instr.operands[0].imm, m_thumbArch);
        }
        else if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_LR)
        {
          result.AddBranch(FunctionReturn);
          /* if (instr.operands[0].reg == REG_LR)
          {
            result.AddBranch(FunctionReturn);
          }
          else
          {
            result.AddBranch(CallDestination, 0);
          } */
        }
      }
      break;
    case ARMV5_BX:
      if (UNCONDITIONAL(instr.cond))
      {
        result.archTransitionByTargetAddr = true;
        if (instr.operands[0].reg == REG_LR)
          result.AddBranch(FunctionReturn);
        else
          result.AddBranch(UnresolvedBranch);
      }
      else if (instr.operands[0].reg == REG_LR)
      {
        result.AddBranch(FalseBranch, addr + 4, this);
      }
      break;
    case ARMV5_B:
      if (UNCONDITIONAL(instr.cond))
      {
        result.AddBranch(UnconditionalBranch, instr.operands[0].imm, this);
      }
      else
      {
        result.AddBranch(TrueBranch, instr.operands[0].imm, this);
        result.AddBranch(FalseBranch, addr + 4, this);
      }
      break;

    case ARMV5_LDR:
      /* Check for PC load (indirect branch) */
      if (instr.operands[0].reg == REG_PC)
      {
        result.archTransitionByTargetAddr = true;
        result.AddBranch(UnresolvedBranch);
        /* Conditional LDR PC can fall through */
        if (CONDITIONAL(instr.cond))
        {
          result.AddBranch(FalseBranch, addr + 4, this);
        }
      }
      break;

    case ARMV5_LDM:
    case ARMV5_LDMIA:
    case ARMV5_LDMIB:
    case ARMV5_LDMDA:
    case ARMV5_LDMDB:
      /* Match ARMv7 behavior for PC in register list */
      if (UNCONDITIONAL(instr.cond))
      {
        for (int i = 0; i < MAX_OPERANDS; i++)
        {
          if (instr.operands[i].cls == NONE)
            break;
          if (instr.operands[i].cls == REG_LIST)
          {
            uint32_t regList = instr.operands[i].imm;
            if (regList == (1U << REG_PC))
            {
              result.archTransitionByTargetAddr = true;
              result.AddBranch(UnresolvedBranch);
            }
            else if (regList & (1U << REG_PC))
            {
              result.AddBranch(FunctionReturn);
            }
            break;
          }
        }
      }
      break;

    case ARMV5_POP:
      /* POP with PC in list is a return (matches ARMv7) */
      for (int i = 0; i < MAX_OPERANDS; i++)
      {
        if (instr.operands[i].cls == NONE)
          break;
        if (instr.operands[i].cls == REG_LIST)
        {
          uint32_t regList = instr.operands[i].imm;
          if (regList & (1U << REG_PC))
          {
            result.AddBranch(FunctionReturn);
            if (CONDITIONAL(instr.cond))
              result.AddBranch(FalseBranch, addr + 4, this);
          }
          break;
        }
      }
      break;

    case ARMV5_MOV:
      /* MOV PC, LR is a return */
      if (instr.operands[0].reg == REG_PC && instr.operands[1].reg == REG_LR)
      {
        result.archTransitionByTargetAddr = true;
        result.AddBranch(FunctionReturn);
        if (CONDITIONAL(instr.cond))
        {
          result.AddBranch(FalseBranch, addr + 4, this);
        }
      }
      else if (instr.operands[0].reg == REG_PC)
      {
        result.archTransitionByTargetAddr = true;
        result.AddBranch(UnresolvedBranch);
        if (CONDITIONAL(instr.cond))
        {
          result.AddBranch(FalseBranch, addr + 4, this);
        }
      }
      break;

    case ARMV5_SWI:
    case ARMV5_SVC:
      result.AddBranch(SystemCall);
      break;

    case ARMV5_ADC:
    case ARMV5_ADCS:
    case ARMV5_ADD:
    case ARMV5_ADDS:
    case ARMV5_AND:
    case ARMV5_ANDS:
    case ARMV5_ASR:
    case ARMV5_ASRS:
    case ARMV5_BIC:
    case ARMV5_BICS:
    case ARMV5_EOR:
    case ARMV5_EORS:
    case ARMV5_LSL:
    case ARMV5_LSLS:
    case ARMV5_LSR:
    case ARMV5_LSRS:
    case ARMV5_MVN:
    case ARMV5_MVNS:
    case ARMV5_ORR:
    case ARMV5_ORRS:
    case ARMV5_ROR:
    case ARMV5_RORS:
    case ARMV5_RSB:
    case ARMV5_RSBS:
    case ARMV5_RSC:
    case ARMV5_SBC:
    case ARMV5_SBCS:
    case ARMV5_SUB:
    case ARMV5_SUBS:
      /* Data processing with PC as destination is a computed jump (matches ARMv7) */
      if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
      {
        result.archTransitionByTargetAddr = true;
        result.AddBranch(UnresolvedBranch);
        if (CONDITIONAL(instr.cond))
        {
          result.AddBranch(FalseBranch, addr + 4, this);
        }
      }
      break;

    default:
      break;
    }
  }

  bool GetCoalescedLowLevelIL(const uint8_t *data, uint64_t addr, size_t &len, LowLevelILFunction &il, Instruction &instr)
  {
    size_t remaining = len / 4;
    if (remaining > COALESCE_MAX_INSTRS)
      remaining = COALESCE_MAX_INSTRS;

    Condition cond = instr.cond;

    Instruction coalesced[COALESCE_MAX_INSTRS];
    bool liftInstruction[COALESCE_MAX_INSTRS];
    size_t disassembled = 1;

    coalesced[0] = instr;
    liftInstruction[0] = true;

    auto setsFlags = [](const Instruction &instr)
    {
      if (instr.setsFlags)
        return true;

      switch (instr.operation)
      {
      case ARMV5_CMP:
      case ARMV5_CMN:
      case ARMV5_TST:
        return true;

      case ARMV5_BL:
      case ARMV5_BLX:
        return true;

      default:
        return false;
      }
    };

    for (bool condValid[2] = {true, true}; (disassembled < remaining) && (condValid[0] || condValid[1]); disassembled++)
    {
      size_t consumed = disassembled * 4;
      auto &newInstr = coalesced[disassembled];

      if (!Disassemble(data + consumed, addr + consumed, len - consumed, newInstr))
        break;
      if (UNCONDITIONAL(newInstr.cond))
        break;
      if (!IsRelatedCondition(newInstr.cond, cond))
        break;

      liftInstruction[disassembled] = condValid[newInstr.cond != cond];
      if (!CanCoalesceAfterInstruction(newInstr))
        condValid[newInstr.cond != cond] = false;

      if (setsFlags(instr))
      {
        condValid[0] = true;
        condValid[1] = true;
      }
    }

    if (disassembled == 1)
    {
      len = 4;
      return GetLowLevelILForArmInstruction(this, addr, il, instr, 4);
    }

    LowLevelILLabel doneLabel;
    LowLevelILLabel condLabels[2];

    BNLowLevelILLabel *doneLabelExisting = il.GetLabelForAddress(this, addr + (disassembled * 4));
    BNLowLevelILLabel *doneLabelToUse = doneLabelExisting ? doneLabelExisting : &doneLabel;

    for (size_t blockStart = 0; blockStart < disassembled;)
    {
      auto &beginInstr = coalesced[blockStart];
      size_t stateIdx = (beginInstr.cond != cond);

      // determine how many instructions to lift this iteration.
      // generally, this will be set to `disassembled`, but in the
      // event that cmp/cmn/tst instructions are used in the conditional
      // block, they each require re-evaluation of the condition on the side
      // that executed the flag setting instructions
      size_t nextFlagSet = blockStart;
      for (; nextFlagSet < disassembled; nextFlagSet++)
      {
        if (!liftInstruction[nextFlagSet])
          continue; // skip unreachable instructions

        if (setsFlags(coalesced[nextFlagSet]))
          break;
      }

      // figure out where the next block start for the *other* condition in the sequence is
      size_t otherCondNext = blockStart + 1;
      for (; otherCondNext < disassembled; otherCondNext++)
      {
        if (!liftInstruction[otherCondNext])
          continue; // skip unreachable instructions

        if (coalesced[otherCondNext].cond != beginInstr.cond)
          break;
      }

      bool hasOtherPath = (otherCondNext < disassembled);

      il.SetCurrentAddress(this, addr + (blockStart * 4));
      il.AddInstruction(il.If(GetCondition(il, beginInstr.cond), condLabels[stateIdx],
                              hasOtherPath ? condLabels[1 - stateIdx] : *doneLabelToUse));

      auto liftInstructions = [&](Condition liftCond)
      {
        size_t stateIdx = (liftCond != cond);

        il.MarkLabel(condLabels[stateIdx]);
        condLabels[stateIdx] = LowLevelILLabel();

        bool exhausted = true;
        for (size_t i = nextFlagSet + 1; (i < disassembled) && exhausted; i++)
          if (coalesced[i].cond == liftCond)
            exhausted = false;

        size_t liftIdx = blockStart;
        for (; (liftIdx <= nextFlagSet) && (liftIdx < disassembled); liftIdx++)
        {
          if (!liftInstruction[liftIdx])
            continue; // skip unreachable instructions

          auto &curInstr = coalesced[liftIdx];
          if (curInstr.cond != liftCond)
            continue;

          uint64_t instrAddr = addr + (liftIdx * 4);

          il.SetCurrentAddress(this, instrAddr);

          curInstr.cond = COND_AL;
          GetLowLevelILForArmInstruction(this, instrAddr, il, curInstr, 4);
          curInstr.cond = liftCond;
        }

        // CASE 1: last instr was a flag-setting instruction, do nothing, next lifting fixes it
        if ((nextFlagSet < disassembled) && (coalesced[nextFlagSet].cond == liftCond))
          return;

        // CASE 2: no further instructions with this cond exist: goto done
        else if (exhausted)
          il.AddInstruction(il.Goto(*doneLabelToUse));

        // CASE 3: last instr was not a flag-setting instruction, goto next block of this cond (or end)
        else
          il.AddInstruction(il.Goto(condLabels[stateIdx]));
      };

      bool liftAfter = false;
      if (hasOtherPath && (otherCondNext <= nextFlagSet))
      {
        // if we have two different cases to lift, and one of them contains a flag-setting
        // instruction, make sure the condition with the the flag-setting instruction is
        // lifted last. this lets us avoid an unnecessary LLIL_GOTO to the next if statement
        if ((nextFlagSet < disassembled) && (coalesced[nextFlagSet].cond == beginInstr.cond))
          liftInstructions(coalesced[otherCondNext].cond);
        else
          liftAfter = true;
      }

      liftInstructions(beginInstr.cond);

      if (liftAfter)
        liftInstructions(coalesced[otherCondNext].cond);

      blockStart = nextFlagSet + 1;
    }

    if (!doneLabelExisting)
      il.MarkLabel(doneLabel);

    len = disassembled * 4;
    return (doneLabelExisting == nullptr);
  }

public:
  Armv5Architecture(const char *name, BNEndianness endian)
      : ArmCommonArchitecture(name, endian)
  {
  }

  virtual size_t GetInstructionAlignment() const override
  {
    return 4;
  }

  virtual size_t GetMaxInstructionLength() const override
  {
    return 4;  // ARM instructions are always 4 bytes
  }

  virtual size_t GetOpcodeDisplayLength() const override
  {
    return 4;
  }

  virtual std::vector<uint32_t> GetSystemRegisters() override
  {
    return {REG_CPSR, REG_SPSR, REG_FPSCR};
  }

  /*
   * Check if an instruction word looks like a function prologue.
   * ARM function prologues typically:
   * - PUSH {regs} or STMFD SP!, {regs} - save registers
   * - MOV R11, SP or MOV R7, SP - set up frame pointer
   * - SUB SP, SP, #imm - allocate stack space
   *
   * Returns true if this looks like a function start.
   */
  bool IsFunctionPrologue(uint32_t instrWord)
  {
    // PUSH {regs} - encoded as STMDB SP!, {regs} with writeback
    // Encoding: cond 100 1 0 0 1 0 1101 reglist
    // Mask: 0x0FFF0000, expect: 0x092D0000 (unconditional: 0xE92D0000)
    if ((instrWord & 0x0FFF0000) == 0x092D0000)
    {
      uint16_t reglist = instrWord & 0xFFFF;
      // Valid prologue typically saves LR and possibly other regs
      // At minimum, PUSH {LR} (reglist bit 14 set)
      if (reglist & (1 << 14))  // LR is saved
        return true;
      // Or saves multiple registers (r4-r11 range)
      if (__builtin_popcount(reglist & 0x0FF0) >= 2)  // At least 2 of r4-r11
        return true;
    }

    // STMFD SP!, {regs} - same encoding, alternate mnemonic
    // Already covered above

    // MOV R11, SP (frame pointer setup) - common in AAPCS
    // Encoding: cond 0001101 S 0000 Rd 00000000 Rm
    // MOV R11, SP: 0xE1A0B00D (Rd=11=0xB, Rm=13=0xD)
    if ((instrWord & 0x0FFFFFFF) == 0x01A0B00D)
      return true;

    // MOV R7, SP (Thumb-compatible frame pointer)
    // MOV R7, SP: 0xE1A0700D (Rd=7, Rm=13)
    if ((instrWord & 0x0FFFFFFF) == 0x01A0700D)
      return true;

    // SUB SP, SP, #imm (stack allocation) - can be a prologue indicator
    // Encoding: cond 0010 0100 1101 1101 imm12
    // Mask: 0x0FFF0000, expect: 0x024DD000
    if ((instrWord & 0x0FFF0000) == 0x024DD000)
    {
      // Only count as prologue if allocating reasonable stack (4-4096 bytes)
      uint32_t imm12 = instrWord & 0xFFF;
      uint32_t rotate = (imm12 >> 8) & 0xF;
      uint32_t imm8 = imm12 & 0xFF;
      uint32_t stackSize = (imm8 >> (rotate * 2)) | (imm8 << (32 - rotate * 2));
      if (stackSize >= 4 && stackSize <= 4096)
        return true;
    }

    return false;
  }

  /*
   * Check if an instruction word looks like a function epilogue.
   * ARM function epilogues typically:
   * - POP {regs, PC} or LDMFD SP!, {regs, PC} - restore registers and return
   * - BX LR - return via link register
   * - MOV PC, LR - return via link register
   *
   * Returns true if this looks like a function end.
   */
  bool IsFunctionEpilogue(uint32_t instrWord)
  {
    // POP {regs, PC} - encoded as LDMIA SP!, {regs} with PC in reglist
    // Encoding: cond 100 0 1 0 1 1 1101 reglist
    // Mask: 0x0FFF0000, expect: 0x08BD0000
    if ((instrWord & 0x0FFF0000) == 0x08BD0000)
    {
      uint16_t reglist = instrWord & 0xFFFF;
      // PC must be in the register list for this to be a return
      if (reglist & (1 << 15))  // PC is loaded
        return true;
    }

    // LDMFD SP!, {regs, PC} - same encoding, alternate mnemonic
    // Already covered above

    // BX LR - return via link register
    // Encoding: cond 0001 0010 1111 1111 1111 0001 Rm
    // BX LR: 0xE12FFF1E (Rm=14=LR)
    if ((instrWord & 0x0FFFFFFF) == 0x012FFF1E)
      return true;

    // MOV PC, LR - return via link register (older style)
    // Encoding: cond 0001101 S 0000 1111 00000000 1110
    // MOV PC, LR: 0xE1A0F00E (Rd=15=PC, Rm=14=LR)
    if ((instrWord & 0x0FFFFFFF) == 0x01A0F00E)
      return true;

    // LDMFD SP!, {regs}^ with PC - return from exception with SPSR restore
    // Encoding: cond 100 0 1 1 0 1 1101 reglist (bit 22 set for ^ modifier)
    // Mask: 0x0FFF0000, expect: 0x08DD0000
    if ((instrWord & 0x0FDF0000) == 0x08DD0000)
    {
      uint16_t reglist = instrWord & 0xFFFF;
      if (reglist & (1 << 15))  // PC is loaded
        return true;
    }

    return false;
  }

  /*
   * Check if an instruction word looks like literal pool data rather than code.
   * Literal pools contain constants loaded via PC-relative LDR instructions.
   * Common patterns:
   * - Addresses (0x10xxxxxx, 0x11xxxxxx, etc.)
   * - Small constants that look like addresses
   * - MMIO addresses (0x90xxxxxx, 0xDCxxxxxx, etc.)
   *
   * This is checked AFTER IsLikelyData() - it catches values that decode
   * to valid instructions but are actually data.
   */
  bool IsLikelyLiteralPoolEntry(uint32_t instrWord, uint64_t addr)
  {
    // Address-like patterns common in literal pools:
    // - ROM addresses: 0x00xxxxxx, 0x10xxxxxx, 0x11xxxxxx, 0x13xxxxxx
    // - SRAM addresses: 0xA4xxxxxx
    // - MMIO addresses: 0x90xxxxxx, 0xDCxxxxxx

    uint32_t highByte = (instrWord >> 24) & 0xFF;

    // Common firmware base addresses
    if (highByte == 0x10 || highByte == 0x11 || highByte == 0x12 || highByte == 0x13)
    {
      // Check if it looks like an aligned address
      if ((instrWord & 0x3) == 0)  // 4-byte aligned
        return true;
    }

    // SRAM/uncached RAM alias range
    if (highByte == 0xA4)
    {
      if ((instrWord & 0x3) == 0)
        return true;
    }

    // MMIO/peripheral ranges
    if (highByte == 0x90 || highByte == 0x91 || highByte == 0xDC)
    {
      if ((instrWord & 0x3) == 0)
        return true;
    }

    // Zero or small positive constants (common in literal pools)
    // But be careful - these can also be NOP or valid instructions
    // Only flag as literal pool if it's a suspiciously round number
    if (instrWord == 0x00000000)
      return false;  // Could be NOP (andeq r0, r0, r0), let other checks handle it

    return false;
  }

  /*
   * Heuristic to detect instruction patterns that are likely data, not code.
   * ARM's dense instruction encoding means almost any 32-bit value decodes to
   * something, but certain patterns are very unlikely to appear in real code.
   *
   * PERFORMANCE: Checks are ordered from cheapest to most expensive:
   * 1. Pure bit pattern checks (no struct access)
   * 2. Simple operation enum checks
   * 3. Register/operand field checks
   * 4. Loop-based checks (most expensive)
   *
   * Reference: firebird emulator disasm.c uses mask-value tables with explicit
   * invalid patterns marked as "???"
   */
  bool IsLikelyData(uint32_t instrWord, const Instruction& instr)
  {
    // Extract commonly used bit fields once
    uint32_t cond = (instrWord >> 28) & 0xF;
    uint32_t bits27_25 = (instrWord >> 25) & 0x7;
    uint32_t highByte = (instrWord >> 24) & 0xFF;

    // === FAST PATH: Pure bit pattern checks (no struct access) ===

    // Pattern 1: Condition code 0xF with invalid encoding
    // Only PLD, BLX (immediate), and coprocessor instructions are valid
    if (cond == 0xF)
    {
      // Coprocessor instructions (bits 27:24 = 1100, 1101, 1110) are valid
      uint32_t bits27_24 = highByte & 0xF;
      bool isCoproc = (bits27_24 >= 0xC && bits27_24 <= 0xE);

      if (instr.operation != ARMV5_BLX && instr.operation != ARMV5_PLD && !isCoproc)
        return true;
    }

    // Pattern: Branch encoding (bits 27:25 = 101) should decode to B/BL
    if (bits27_25 == 0x5)
    {
      if (instr.operation != ARMV5_B && instr.operation != ARMV5_BL)
        return true;
    }

    // Pattern: Coprocessor load/store to invalid coprocessor
    // bits27_25 == 6 covers LDC/STC and MCRR/MRRC instructions
    // Valid coprocessors: p10/p11 (VFP), p14 (debug), p15 (system control)
    if (bits27_25 == 0x6)
    {
      uint32_t cpnum = (instrWord >> 8) & 0xF;
      if (cpnum != 10 && cpnum != 11 && cpnum != 14 && cpnum != 15)
        return true;
    }

    // Pattern: Coprocessor data/transfer to invalid coprocessor
    if (bits27_25 == 0x7)
    {
      uint32_t bit24 = (instrWord >> 24) & 0x1;
      if (bit24 == 0)  // Coprocessor (not SWI)
      {
        uint32_t cpnum = (instrWord >> 8) & 0xF;
        if (cpnum != 10 && cpnum != 11 && cpnum != 14 && cpnum != 15)
          return true;
      }
    }

    // Pattern: Explicitly undefined instruction space
    // ARM architecture reserves this encoding as permanently undefined
    // From ARM ARM: when bits 27:25 = 011, bit 4 = 1, bits 24:20 = 11111
    // Reference: Firebird emulator arm_interpreter.cpp line 430
    if ((instrWord & 0x0FF000F0) == 0x07F000F0)
      return true;

    // Pattern: Invalid multiply encoding
    // Bits 27:25 = 000, bits 7:4 = 1001 is the multiply group
    // If our decoder produced something other than a multiply, it's invalid
    // Reference: Firebird disasm.c line 84: {0xE0000F0, 0x0000090, "???"}
    if ((instrWord & 0x0E0000F0) == 0x00000090)
    {
      // This has the multiply signature - verify it decoded to a valid multiply
      if (instr.operation != ARMV5_MUL && instr.operation != ARMV5_MULS &&
          instr.operation != ARMV5_MLA &&
          instr.operation != ARMV5_UMULL && instr.operation != ARMV5_UMLAL &&
          instr.operation != ARMV5_SMULL && instr.operation != ARMV5_SMLAL &&
          instr.operation != ARMV5_SWP && instr.operation != ARMV5_SWPB &&
          // DSP multiplies also use this encoding space
          instr.operation != ARMV5_SMULBB && instr.operation != ARMV5_SMULBT &&
          instr.operation != ARMV5_SMULTB && instr.operation != ARMV5_SMULTT &&
          instr.operation != ARMV5_SMULWB && instr.operation != ARMV5_SMULWT &&
          instr.operation != ARMV5_SMLABB && instr.operation != ARMV5_SMLABT &&
          instr.operation != ARMV5_SMLATB && instr.operation != ARMV5_SMLATT &&
          instr.operation != ARMV5_SMLAWB && instr.operation != ARMV5_SMLAWT &&
          instr.operation != ARMV5_SMLALBB && instr.operation != ARMV5_SMLALBT &&
          instr.operation != ARMV5_SMLALTB && instr.operation != ARMV5_SMLALTT &&
          // Saturating adds also share the encoding
          instr.operation != ARMV5_QADD && instr.operation != ARMV5_QSUB &&
          instr.operation != ARMV5_QDADD && instr.operation != ARMV5_QDSUB)
        return true;
    }

    // === MEDIUM PATH: Simple operation enum checks ===

    // RSC (Reverse Subtract with Carry) is extremely rare
    if (instr.operation == ARMV5_RSC)
      return true;

    // Pattern: Long multiply with unusual flags/registers
    if (instr.operation == ARMV5_UMULL || instr.operation == ARMV5_UMLAL ||
        instr.operation == ARMV5_SMULL || instr.operation == ARMV5_SMLAL)
    {
      // Conditional + S flag together is extremely rare for 64-bit multiply
      if (instr.setsFlags && CONDITIONAL(instr.cond))
        return true;

      // Check for overlapping RdLo/RdHi with Rm/Rs (UNPREDICTABLE)
      if (instr.operands[0].reg == instr.operands[2].reg ||
          instr.operands[0].reg == instr.operands[3].reg ||
          instr.operands[1].reg == instr.operands[2].reg ||
          instr.operands[1].reg == instr.operands[3].reg)
        return true;

      // Destination to LR or PC is very unusual
      if (instr.operands[0].cls == REG &&
          (instr.operands[0].reg == REG_LR || instr.operands[0].reg == REG_PC))
        return true;
      if (instr.operands[1].cls == REG &&
          (instr.operands[1].reg == REG_LR || instr.operands[1].reg == REG_PC))
        return true;

      // Source from PC or SP is unusual
      if (instr.operands[2].cls == REG &&
          (instr.operands[2].reg == REG_PC || instr.operands[2].reg == REG_SP))
        return true;
      if (instr.operands[3].cls == REG &&
          (instr.operands[3].reg == REG_PC || instr.operands[3].reg == REG_SP))
        return true;
    }

    // Pattern: Compare/test with PC as Rn
    if (instr.operation == ARMV5_TST || instr.operation == ARMV5_TEQ ||
        instr.operation == ARMV5_CMP || instr.operation == ARMV5_CMN)
    {
      if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
        return true;
    }

    // Pattern: ADC/SBC with LR as destination
    if ((instr.operation == ARMV5_ADC || instr.operation == ARMV5_ADCS ||
         instr.operation == ARMV5_SBC || instr.operation == ARMV5_SBCS) &&
        instr.operands[0].cls == REG && instr.operands[0].reg == REG_LR)
      return true;

    // Pattern: Data processing with PC as source (except ADD/SUB/MOV)
    if (instr.operands[1].cls == REG && instr.operands[1].reg == REG_PC)
    {
      if (instr.operation != ARMV5_ADD && instr.operation != ARMV5_ADDS &&
          instr.operation != ARMV5_SUB && instr.operation != ARMV5_SUBS &&
          instr.operation != ARMV5_MOV && instr.operation != ARMV5_MOVS)
        return true;
    }

    // === SLOWER PATH: Loop-based and address pattern checks ===

    // Pattern: SP as shift amount register (loop through operands)
    for (int i = 0; i < MAX_OPERANDS; i++)
    {
      if (instr.operands[i].cls == NONE)
        break;
      if (instr.operands[i].flags.offsetRegUsed && instr.operands[i].offset == REG_SP)
        return true;
    }

    // === ADDRESS PATTERN CHECKS: Detect common literal pool values ===
    // These are addresses that decode to valid-looking instructions but are actually data

    // 0x10xxxxxx - 0x13xxxxxx: ROM/Flash addresses
    // Check if 4-byte aligned and decodes to suspicious instruction
    if (highByte >= 0x10 && highByte <= 0x13 && (instrWord & 0x3) == 0)
    {
      // ADC/SBC with conditional + S flag is rare in real code
      if ((instr.operation == ARMV5_ADC || instr.operation == ARMV5_ADCS ||
           instr.operation == ARMV5_SBC || instr.operation == ARMV5_SBCS) &&
          CONDITIONAL(instr.cond) && instr.setsFlags)
        return true;
    }

    // 0xA4xxxxxx: SRAM addresses (decode to various instructions)
    if (highByte == 0xA4)
    {
      if ((instrWord & 0x3) == 0)
      {
        // SRAM addresses commonly decode to BCS/BCC (0xAxxxxxxx branch encoding)
        // but with suspicious target addresses
        if (instr.operation == ARMV5_B)
        {
          // Branch target would be way outside any reasonable code range
          // If the instruction decodes as a branch but the offset would be huge
          int32_t offset = (instrWord & 0x00FFFFFF);
          if (offset & 0x800000)
            offset |= 0xFF000000;  // Sign extend
          // If branch offset > 16MB, likely data
          if (offset > 0x1000000 || offset < -0x1000000)
            return true;
        }
      }
    }

    // 0x90xxxxxx, 0xDCxxxxxx: MMIO addresses
    if (highByte == 0x90 || highByte == 0x91 || highByte == 0xDC)
    {
      if ((instrWord & 0x3) == 0)
      {
        // MMIO addresses decode to various coprocessor or multiply patterns
        // If we got here without matching earlier coprocessor checks, flag it
        if (bits27_25 == 0x0)  // Data processing (register)
        {
          // Check for multiply operations with unusual register combos
          // 0x90xxxxxx often decodes to MUL/MLA variants
          if (instr.operation == ARMV5_MUL || instr.operation == ARMV5_MLA)
          {
            // Check for PC/SP as operands (unusual for multiply)
            for (int i = 0; i < MAX_OPERANDS && instr.operands[i].cls != NONE; i++)
            {
              if (instr.operands[i].cls == REG &&
                  (instr.operands[i].reg == REG_PC || instr.operands[i].reg == REG_SP))
                return true;
            }
          }
        }
      }
    }

    return false;
  }

  virtual bool GetInstructionInfo(const uint8_t *data, uint64_t addr, size_t maxLen, InstructionInfo &result) override
  {
    if (maxLen < 4)
      return false;
    Instruction instr;
    if (!Disassemble(data, addr, maxLen, instr))
      return false;

    /* Return false for undefined/unpredictable instructions - matches ARMv7 pattern */
    if (instr.operation == ARMV5_UNDEFINED || instr.operation == ARMV5_UDF ||
      instr.operation == ARMV5_UNPREDICTABLE)
  {
    return false;
  }

    /* Check for patterns that are likely data, not code */
    uint32_t instrWord = *(const uint32_t*)data;
    if (IsLikelyData(instrWord, instr))
  {
    return false;
  }

    SetInstructionInfoForInstruction(addr, instr, result);
    return true;
  }

  virtual bool GetInstructionText(const uint8_t *data, uint64_t addr, size_t &len,
                                  std::vector<InstructionTextToken> &result) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, 4, instr))
    {
      len = 4;
      return false;
    }

    /* Return false for undefined/unpredictable instructions - matches ARMv7 pattern */
    if (instr.operation == ARMV5_UNDEFINED || instr.operation == ARMV5_UDF ||
        instr.operation == ARMV5_UNPREDICTABLE)
    {
      len = 4;
      return false;
    }

    /* Check for patterns that are likely data, not code */
    uint32_t instrWord = *(const uint32_t*)data;
    if (IsLikelyData(instrWord, instr))
    {
      len = 4;
      return false;
    }

    len = 4;

    int operandCount = GetOperandCount(instr);

    /* Operation name */
    const char *opname = get_operation(instr.operation);
    const char *cond = "";
    if (CONDITIONAL(instr.cond))
    {
      cond = get_condition(instr.cond);
    }
    auto allowsSuffixS = [](Operation op)
    {
      switch (op)
      {
      case ARMV5_AND:
      case ARMV5_EOR:
      case ARMV5_SUB:
      case ARMV5_RSB:
      case ARMV5_ADD:
      case ARMV5_ADC:
      case ARMV5_SBC:
      case ARMV5_RSC:
      case ARMV5_ORR:
      case ARMV5_MOV:
      case ARMV5_BIC:
      case ARMV5_MVN:
        return true;
      default:
        return false;
      }
    };
    const char *s = (instr.setsFlags && allowsSuffixS(instr.operation)) ? "s" : "";

    string mnemonic = string(opname) + cond + s;
    result.emplace_back(InstructionToken, mnemonic);

    if (operandCount > 0)
    {
      result.emplace_back(TextToken, " ");
    }

    for (int i = 0; i < operandCount; i++)
    {
      if (i > 0)
      {
        result.emplace_back(OperandSeparatorToken, ", ");
      }

      const InstructionOperand &op = instr.operands[i];

      switch (op.cls)
      {
      case REG:
      {
        const char *name = get_register_name(op.reg);
        if (name)
        {
          result.emplace_back(RegisterToken, name, (uint32_t)op.reg);
        }
        else if (op.reg >= REG_S0 && op.reg <= REG_S31)
        {
          char buf[8];
          snprintf(buf, sizeof(buf), "s%d", op.reg - REG_S0);
          result.emplace_back(RegisterToken, buf, (uint32_t)op.reg);
        }
        else if (op.reg >= REG_D0 && op.reg <= REG_D15)
        {
          char buf[8];
          snprintf(buf, sizeof(buf), "d%d", op.reg - REG_D0);
          result.emplace_back(RegisterToken, buf, (uint32_t)op.reg);
        }
        if (op.shift != SHIFT_NONE)
        {
          result.emplace_back(TextToken, ", ");
          result.emplace_back(TextToken, get_shift(op.shift));
          result.emplace_back(TextToken, " ");
          if (op.flags.offsetRegUsed && op.offset != REG_INVALID)
          {
            const char *offsetName = get_register_name(op.offset);
            if (offsetName)
              result.emplace_back(RegisterToken, offsetName, (uint32_t)op.offset);
          }
          else
          {
            char buf[16];
            snprintf(buf, sizeof(buf), "#0x%x", op.imm);
            result.emplace_back(TextToken, buf);
          }
        }
        if (op.flags.wb && op.cls == REG)
        {
          result.emplace_back(TextToken, "!");
        }
        break;
      }

      case REG_COPROCP:
      {
        /* Coprocessor number: p0-p15 */
        char buf[8];
        snprintf(buf, sizeof(buf), "p%d", op.reg);
        result.emplace_back(RegisterToken, buf, (uint32_t)op.reg);
        break;
      }

      case REG_COPROCC:
      {
        /* Coprocessor register: c0-c15 */
        char buf[8];
        snprintf(buf, sizeof(buf), "c%d", op.reg);
        result.emplace_back(RegisterToken, buf, (uint32_t)op.reg);
        break;
      }

      case COPROC_OPC:
      {
        /* Coprocessor opcode: plain number without # prefix */
        char buf[8];
        snprintf(buf, sizeof(buf), "%d", (int)op.imm);
        result.emplace_back(IntegerToken, buf, op.imm);
        break;
      }

      case IMM:
      {
        char buf[32];
        snprintf(buf, sizeof(buf), "#0x%llx", (unsigned long long)op.imm);
        result.emplace_back(IntegerToken, buf, op.imm);
        break;
      }

      case LABEL:
      {
        /* For load/store, wrap in brackets to show memory dereference */
        bool isLoadStore = (instr.operation == ARMV5_LDR || instr.operation == ARMV5_LDRB ||
                            instr.operation == ARMV5_LDRH || instr.operation == ARMV5_LDRSB ||
                            instr.operation == ARMV5_LDRSH || instr.operation == ARMV5_LDRD ||
                            instr.operation == ARMV5_STR || instr.operation == ARMV5_STRB ||
                            instr.operation == ARMV5_STRH || instr.operation == ARMV5_STRD);
        if (isLoadStore)
        {
          result.emplace_back(BeginMemoryOperandToken, "[");
        }
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)op.imm);
        result.emplace_back(PossibleAddressToken, buf, op.imm);
        if (isLoadStore)
        {
          result.emplace_back(EndMemoryOperandToken, "]");
        }
        break;
      }

      case REG_LIST:
      {
        result.emplace_back(BeginMemoryOperandToken, "{");
        bool first = true;
        uint32_t regList = op.imm;
        for (int r = 0; r < 16; r++)
        {
          if (regList & (1 << r))
          {
            if (!first)
            {
              result.emplace_back(OperandSeparatorToken, ", ");
            }
            const char *regName = get_register_name((::Register)r);
            if (regName)
              result.emplace_back(RegisterToken, regName, r);
            first = false;
          }
        }
        result.emplace_back(EndMemoryOperandToken, "}");
        /* Add ^ suffix if S bit was set (user mode / exception return) */
        if (op.flags.wb)
          result.emplace_back(OperationToken, " ^");
        break;
      }

      case MEM_IMM:
      case MEM_REG:
      case MEM_PRE_IDX:
      case MEM_POST_IDX:
      {
        bool postIndexed = (op.cls == MEM_POST_IDX);

        result.emplace_back(BeginMemoryOperandToken, "[");
        const char *regName = get_register_name(op.reg);
        if (regName)
          result.emplace_back(RegisterToken, regName, (uint32_t)op.reg);

        if (!postIndexed)
        {
          if (op.flags.offsetRegUsed && op.offset != REG_INVALID)
          {
            result.emplace_back(TextToken, ", ");
            if (!op.flags.add)
              result.emplace_back(TextToken, "-");
            const char *offsetName = get_register_name(op.offset);
            if (offsetName)
              result.emplace_back(RegisterToken, offsetName, (uint32_t)op.offset);
            if (op.shift != SHIFT_NONE)
            {
              result.emplace_back(TextToken, ", ");
              result.emplace_back(TextToken, get_shift(op.shift));
              char buf[16];
              snprintf(buf, sizeof(buf), " #0x%x", op.imm);
              result.emplace_back(IntegerToken, buf, op.imm);
            }
          }
          else if (op.imm != 0)
          {
            long long v = (long long)(int32_t)op.imm;
            if (!op.flags.add)
              v = -v;
            unsigned long long absv = (unsigned long long)(v < 0 ? -v : v);
            char buf[32];
            snprintf(buf, sizeof(buf), ", #%s0x%llx", v < 0 ? "-" : "", absv);
            result.emplace_back(TextToken, buf);
          }
          result.emplace_back(EndMemoryOperandToken, "]");
          if (op.flags.wb)
          {
            result.emplace_back(TextToken, "!");
          }
        }
        else
        {
          result.emplace_back(EndMemoryOperandToken, "]");
          result.emplace_back(TextToken, ", ");
          if (op.flags.offsetRegUsed && op.offset != REG_INVALID)
          {
            if (!op.flags.add)
              result.emplace_back(TextToken, "-");
            const char *offsetName = get_register_name(op.offset);
            if (offsetName)
              result.emplace_back(RegisterToken, offsetName, (uint32_t)op.offset);
          }
          else
          {
            long long v = (long long)(int32_t)op.imm;
            if (!op.flags.add)
              v = -v;
            unsigned long long absv = (unsigned long long)(v < 0 ? -v : v);
            char buf[32];
            snprintf(buf, sizeof(buf), "#%s0x%llx", v < 0 ? "-" : "", absv);
            result.emplace_back(IntegerToken, buf, op.imm);
          }
        }
        break;
      }

      case SYS_REG:
        if (op.reg == REG_CPSR)
        {
          result.emplace_back(RegisterToken, "cpsr");
        }
        else if (op.reg == REG_SPSR)
        {
          result.emplace_back(RegisterToken, "spsr");
        }
        else if (op.reg == REG_FPSCR)
        {
          result.emplace_back(RegisterToken, "fpscr");
        }
        else if (op.reg == REG_FPSID)
        {
          result.emplace_back(RegisterToken, "fpsid");
        }
        else if (op.reg == REG_FPEXC)
        {
          result.emplace_back(RegisterToken, "fpexc");
        }
        else
        {
          // For CPSR/SPSR with flags mask, use the register name directly
          const char* name = get_register_name(op.reg);
          result.emplace_back(RegisterToken, name ? name : "???");
        }
        break;

      case FIMM:
      {
        /* Floating-point immediate (used for VCMP/VCMPE with zero) */
        char buf[32];
        snprintf(buf, sizeof(buf), "#%.1f", (double)op.immf);
        result.emplace_back(IntegerToken, buf, (uint64_t)0);
        break;
      }

      default:
        break;
      }
    }

    return true;
  }

  virtual bool GetInstructionLowLevelIL(const uint8_t *data, uint64_t addr, size_t &len,
                                        LowLevelILFunction &il) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
    {
      il.AddInstruction(il.Undefined());
      len = 4;
      return false;
    }

    /* Return false for undefined/unpredictable instructions - matches ARMv7 pattern */
    if (instr.operation == ARMV5_UNDEFINED || instr.operation == ARMV5_UDF ||
        instr.operation == ARMV5_UNPREDICTABLE)
    {
      il.AddInstruction(il.Undefined());
      len = 4;
      return false;
    }

    /* Treat likely data as invalid instructions */
    uint32_t instrWord = *(const uint32_t*)data;
    if (IsLikelyData(instrWord, instr))
    {
      il.AddInstruction(il.Undefined());
      len = 4;
      return false;
    }

    /* Use coalescing for conditional instructions */
    if (!UNCONDITIONAL(instr.cond))
      return GetCoalescedLowLevelIL(data, addr, len, il, instr);

    len = 4;
    return GetLowLevelILForArmInstruction(this, addr, il, instr, 4);
  }

  virtual string GetIntrinsicName(uint32_t intrinsic) override
  {
    switch (intrinsic)
    {
    case ARMV5_INTRIN_CLZ:
      return "CountLeadingZeros";
    case ARMV5_INTRIN_QADD:
      return "SaturatingAdd";
    case ARMV5_INTRIN_QSUB:
      return "SaturatingSub";
    case ARMV5_INTRIN_QDADD:
      return "SaturatingDoubleAdd";
    case ARMV5_INTRIN_QDSUB:
      return "SaturatingDoubleSub";
    case ARMV5_INTRIN_SMULBB:
      return "SignedMulBottomBottom";
    case ARMV5_INTRIN_SMULBT:
      return "SignedMulBottomTop";
    case ARMV5_INTRIN_SMULTB:
      return "SignedMulTopBottom";
    case ARMV5_INTRIN_SMULTT:
      return "SignedMulTopTop";
    case ARMV5_INTRIN_SMULWB:
      return "SignedMulWordBottom";
    case ARMV5_INTRIN_SMULWT:
      return "SignedMulWordTop";
    case ARMV5_INTRIN_SMLABB:
      return "SignedMulAccBottomBottom";
    case ARMV5_INTRIN_SMLABT:
      return "SignedMulAccBottomTop";
    case ARMV5_INTRIN_SMLATB:
      return "SignedMulAccTopBottom";
    case ARMV5_INTRIN_SMLATT:
      return "SignedMulAccTopTop";
    case ARMV5_INTRIN_SMLAWB:
      return "SignedMulAccWordBottom";
    case ARMV5_INTRIN_SMLAWT:
      return "SignedMulAccWordTop";
    case ARMV5_INTRIN_SMLALBB:
      return "SignedMulAccLongBottomBottom";
    case ARMV5_INTRIN_SMLALBT:
      return "SignedMulAccLongBottomTop";
    case ARMV5_INTRIN_SMLALTB:
      return "SignedMulAccLongTopBottom";
    case ARMV5_INTRIN_SMLALTT:
      return "SignedMulAccLongTopTop";
    case ARMV5_INTRIN_MRS:
      return "__get_CPSR";  /* MRS Rd, CPSR - like IDA */
    case ARMV5_INTRIN_MSR:
      return "__set_CPSR";  /* MSR CPSR, Rm - like IDA */
    case ARMV5_INTRIN_CDP:
      return "__cdp";       /* CDP - coprocessor data processing */
    case ARMV5_INTRIN_LDC:
      return "__ldc";       /* LDC - load coprocessor */
    case ARMV5_INTRIN_STC:
      return "__stc";       /* STC - store coprocessor */
    case ARMV5_INTRIN_MCR:
    case ARMV5_INTRIN_COPROC_SENDONEWORD:
      return "__mcr";       /* MCR p<cp>, <op1>, Rd, CRn, CRm, <op2> - like IDA */
    case ARMV5_INTRIN_MRC:
    case ARMV5_INTRIN_COPROC_GETONEWORD:
      return "__mrc";       /* MRC p<cp>, <op1>, Rd, CRn, CRm, <op2> - like IDA */
    case ARMV5_INTRIN_SWP:
      return "Swap";
    case ARMV5_INTRIN_SWPB:
      return "SwapByte";
    case ARMV5_INTRIN_BKPT:
      return "Breakpoint";
    case ARMV5_INTRIN_PLD:
      return "PreloadData";
    default:
      return "";
    }
  }

  virtual vector<uint32_t> GetAllIntrinsics() override
  {
    return vector<uint32_t>{
        ARMV5_INTRIN_CLZ,
        ARMV5_INTRIN_QADD,
        ARMV5_INTRIN_QSUB,
        ARMV5_INTRIN_QDADD,
        ARMV5_INTRIN_QDSUB,
        ARMV5_INTRIN_SMULBB,
        ARMV5_INTRIN_SMULBT,
        ARMV5_INTRIN_SMULTB,
        ARMV5_INTRIN_SMULTT,
        ARMV5_INTRIN_SMULWB,
        ARMV5_INTRIN_SMULWT,
        ARMV5_INTRIN_SMLABB,
        ARMV5_INTRIN_SMLABT,
        ARMV5_INTRIN_SMLATB,
        ARMV5_INTRIN_SMLATT,
        ARMV5_INTRIN_SMLAWB,
        ARMV5_INTRIN_SMLAWT,
        ARMV5_INTRIN_SMLALBB,
        ARMV5_INTRIN_SMLALBT,
        ARMV5_INTRIN_SMLALTB,
        ARMV5_INTRIN_SMLALTT,
        ARMV5_INTRIN_MRS,
        ARMV5_INTRIN_MSR,
        ARMV5_INTRIN_COPROC_GETONEWORD,
        ARMV5_INTRIN_COPROC_SENDONEWORD,
        ARMV5_INTRIN_COPROC_GETTWOWORDS,
        ARMV5_INTRIN_COPROC_SENDTWOWORDS,
        ARMV5_INTRIN_CDP,
        ARMV5_INTRIN_LDC,
        ARMV5_INTRIN_STC,
        ARMV5_INTRIN_MCR,
        ARMV5_INTRIN_MRC,
        ARMV5_INTRIN_SWP,
        ARMV5_INTRIN_SWPB,
        ARMV5_INTRIN_BKPT,
        ARMV5_INTRIN_PLD,
    };
  }

  virtual vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override
  {
    switch (intrinsic)
    {
    case ARMV5_INTRIN_CLZ:
      return {NameAndType("value", Type::IntegerType(4, false))};
    case ARMV5_INTRIN_QADD:
    case ARMV5_INTRIN_QSUB:
    case ARMV5_INTRIN_QDADD:
    case ARMV5_INTRIN_QDSUB:
    case ARMV5_INTRIN_SMULBB:
    case ARMV5_INTRIN_SMULBT:
    case ARMV5_INTRIN_SMULTB:
    case ARMV5_INTRIN_SMULTT:
    case ARMV5_INTRIN_SMULWB:
    case ARMV5_INTRIN_SMULWT:
    case ARMV5_INTRIN_SWP:
    case ARMV5_INTRIN_SWPB:
      return {
          NameAndType("a", Type::IntegerType(4, false)),
          NameAndType("b", Type::IntegerType(4, false)),
      };
    case ARMV5_INTRIN_SMLABB:
    case ARMV5_INTRIN_SMLABT:
    case ARMV5_INTRIN_SMLATB:
    case ARMV5_INTRIN_SMLATT:
    case ARMV5_INTRIN_SMLAWB:
    case ARMV5_INTRIN_SMLAWT:
      return {
          NameAndType("a", Type::IntegerType(4, false)),
          NameAndType("b", Type::IntegerType(4, false)),
          NameAndType("acc", Type::IntegerType(4, false)),
      };
    case ARMV5_INTRIN_SMLALBB:
    case ARMV5_INTRIN_SMLALBT:
    case ARMV5_INTRIN_SMLALTB:
    case ARMV5_INTRIN_SMLALTT:
      return {
          NameAndType("a", Type::IntegerType(4, false)),
          NameAndType("b", Type::IntegerType(4, false)),
          NameAndType("accLo", Type::IntegerType(4, false)),
          NameAndType("accHi", Type::IntegerType(4, false)),
      };
    case ARMV5_INTRIN_MRS:
      /* MRS: psr_type (0=CPSR, 1=SPSR) */
      return {
          NameAndType("psr", Type::IntegerType(1, false)),
      };
    case ARMV5_INTRIN_MSR:
      /* MSR: psr_mask, value */
      return {
          NameAndType("psr_mask", Type::IntegerType(1, false)),
          NameAndType("value", Type::IntegerType(4, false)),
      };
    case ARMV5_INTRIN_MRC:
    case ARMV5_INTRIN_COPROC_GETONEWORD:
      /* MRC: cp, opc1, CRn, CRm, opc2 */
      return {
          NameAndType("cp", Type::IntegerType(1, false)),
          NameAndType("opc1", Type::IntegerType(1, false)),
          NameAndType("CRn", Type::IntegerType(1, false)),
          NameAndType("CRm", Type::IntegerType(1, false)),
          NameAndType("opc2", Type::IntegerType(1, false)),
      };
    case ARMV5_INTRIN_MCR:
    case ARMV5_INTRIN_COPROC_SENDONEWORD:
      /* MCR: cp, opc1, value, CRn, CRm, opc2 */
      return {
          NameAndType("cp", Type::IntegerType(1, false)),
          NameAndType("opc1", Type::IntegerType(1, false)),
          NameAndType("value", Type::IntegerType(4, false)),
          NameAndType("CRn", Type::IntegerType(1, false)),
          NameAndType("CRm", Type::IntegerType(1, false)),
          NameAndType("opc2", Type::IntegerType(1, false)),
      };
    case ARMV5_INTRIN_PLD:
      return {
          NameAndType("address", Type::PointerType(4,
                                                   Confidence<Ref<Type>>(Type::VoidType(), 0),
                                                   Confidence<bool>(false),
                                                   Confidence<bool>(false),
                                                   PointerReferenceType)),
      };
    default:
      return vector<NameAndType>();
    }
  }

  virtual vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override
  {
    switch (intrinsic)
    {
    case ARMV5_INTRIN_CLZ:
    case ARMV5_INTRIN_QADD:
    case ARMV5_INTRIN_QSUB:
    case ARMV5_INTRIN_QDADD:
    case ARMV5_INTRIN_QDSUB:
    case ARMV5_INTRIN_SMULBB:
    case ARMV5_INTRIN_SMULBT:
    case ARMV5_INTRIN_SMULTB:
    case ARMV5_INTRIN_SMULTT:
    case ARMV5_INTRIN_SMULWB:
    case ARMV5_INTRIN_SMULWT:
    case ARMV5_INTRIN_SMLABB:
    case ARMV5_INTRIN_SMLABT:
    case ARMV5_INTRIN_SMLATB:
    case ARMV5_INTRIN_SMLATT:
    case ARMV5_INTRIN_SMLAWB:
    case ARMV5_INTRIN_SMLAWT:
    case ARMV5_INTRIN_MRS:
    case ARMV5_INTRIN_MRC:
    case ARMV5_INTRIN_COPROC_GETONEWORD:
    case ARMV5_INTRIN_SWP:
    case ARMV5_INTRIN_SWPB:
      return {Type::IntegerType(4, false)};
    case ARMV5_INTRIN_SMLALBB:
    case ARMV5_INTRIN_SMLALBT:
    case ARMV5_INTRIN_SMLALTB:
    case ARMV5_INTRIN_SMLALTT:
      /* Returns two 32-bit values (64-bit result split) */
      return {Type::IntegerType(4, false), Type::IntegerType(4, false)};
    default:
      return vector<Confidence<Ref<Type>>>();
    }
  }

  virtual bool IsNeverBranchPatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
    return false;
    return (instr.operation == ARMV5_B && CONDITIONAL(instr.cond));
  }

  virtual bool IsAlwaysBranchPatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
    return false;
    return (instr.operation == ARMV5_B && CONDITIONAL(instr.cond));
  }

  virtual bool IsInvertBranchPatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
    return false;
    return (instr.operation == ARMV5_B && CONDITIONAL(instr.cond));
  }

  virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
    return false;
    return (instr.operation == ARMV5_BL) || (instr.operation == ARMV5_BLX);
  }

  virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
    return false;
    return (instr.operation == ARMV5_BL) || (instr.operation == ARMV5_BLX);
  }

  virtual bool ConvertToNop(uint8_t *data, uint64_t addr, size_t len) override
  {
    (void)addr;
    /* ARM NOP: MOV R0, R0 (0xe1a00000) */
    uint32_t nop = 0xe1a00000;
    if (len < sizeof(nop))
      return false;
    for (size_t i = 0; i < len / sizeof(nop); i++)
      ((uint32_t *)data)[i] = nop;
    return true;
  }

  virtual bool AlwaysBranch(uint8_t *data, uint64_t addr, size_t len) override
  {
    (void)addr;
    if (len < 4)
      return false;
    /* Clear condition field (bits 31-28) and set to AL (0xe = always) */
    uint32_t *value = (uint32_t *)data;
    *value = (*value & 0x0fffffff) | (COND_AL << 28);
    return true;
  }

  virtual bool InvertBranch(uint8_t *data, uint64_t addr, size_t len) override
  {
    (void)addr;
    if (len < sizeof(uint32_t))
      return false;
    uint32_t *value = (uint32_t *)data;
    Condition cond = COND_AL;
    switch (*value >> 28)
    {
    case COND_EQ:
      cond = COND_NE;
      break;
    case COND_NE:
      cond = COND_EQ;
      break;
    case COND_CS:
      cond = COND_CC;
      break;
    case COND_CC:
      cond = COND_CS;
      break;
    case COND_MI:
      cond = COND_PL;
      break;
    case COND_PL:
      cond = COND_MI;
      break;
    case COND_VS:
      cond = COND_VC;
      break;
    case COND_VC:
      cond = COND_VS;
      break;
    case COND_HI:
      cond = COND_LS;
      break;
    case COND_LS:
      cond = COND_HI;
      break;
    case COND_GE:
      cond = COND_LT;
      break;
    case COND_LT:
      cond = COND_GE;
      break;
    case COND_GT:
      cond = COND_LE;
      break;
    case COND_LE:
      cond = COND_GT;
      break;
    default:
      return false;
    }
    *value = (*value & 0x0fffffff) | (cond << 28);
    return true;
  }

  virtual bool SkipAndReturnValue(uint8_t *data, uint64_t addr, size_t len, uint64_t value) override
  {
    (void)addr;
    /* Return value is put in R0. The largest value we can put in a single MOV is 12 bits */
    if (value > 0xfff || len < 4)
      return false;

    /* MOV R0, #value (0xe3a00000 | imm12) */
    uint32_t movValueR0 = 0xe3a00000;
    uint32_t *inst = (uint32_t *)data;
    *inst = movValueR0 | (value & 0xfff);
    return true;
  }

  /*
   * Custom analysis for ARM switch table detection.
   *
   * Pattern: ADD PC, PC, Rn (optionally with shift)
   * - Look backward for: ADD Rx, PC, #offset to get table base
   * - Look backward for: LDR Rx, [Rx, Rn, LSL #2] to confirm table access pattern
   * - Look backward for: CMP Rn, #max to get table bounds
   * - Compute all targets: PC_at_jump + 8 + table[i]
   */
  /*
   * Detect ARM switch table pattern and add indirect branch targets.
   *
   * Pattern: ADD PC, PC, Rn (optionally with shift)
   * - Look backward for: ADD Rx, PC, #offset to get table base
   * - Look backward for: CMP Rn, #max to get table bounds
   * - Compute all targets: PC_at_jump + 8 + table[i]
   *
   * This is called from GetInstructionInfo context indirectly through
   * the IndirectBranches provided in the analysis context.
   */
  bool DetectSwitchTable(BinaryView *view, uint64_t jumpAddr,
                         vector<pair<Ref<Architecture>, uint64_t>> &targets)
  {
    /* Read the jump instruction */
    DataBuffer data = view->ReadBuffer(jumpAddr, 4);
    if (data.GetLength() < 4)
      return false;

    Instruction instr;
    if (!Disassemble((const uint8_t *)data.GetData(), jumpAddr, 4, instr))
      return false;

    /* Check for ADD PC, PC, Rn pattern */
    if (instr.operation != ARMV5_ADD)
      return false;
    if (instr.operands[0].cls != REG || instr.operands[0].reg != REG_PC)
      return false;
    if (instr.operands[1].cls != REG || instr.operands[1].reg != REG_PC)
      return false;

    /* Found ADD PC, PC, Rx - scan backward to find table info */
    uint64_t tableBase = 0;
    uint32_t maxCases = 0;
    bool foundTable = false;
    bool hasCmp = false;

    /* Scan up to 16 instructions backward */
    for (int i = 1; i <= 16; i++)
    {
      uint64_t scanAddr = jumpAddr - (i * 4);
      DataBuffer scanData = view->ReadBuffer(scanAddr, 4);
      if (scanData.GetLength() < 4)
        break;

      Instruction scanInstr;
      if (!Disassemble((const uint8_t *)scanData.GetData(), scanAddr, 4, scanInstr))
        continue;

      /* Look for ADD Rx, PC, #imm (table base calculation) */
      if (!foundTable && scanInstr.operation == ARMV5_ADD &&
          scanInstr.operands[1].cls == REG && scanInstr.operands[1].reg == REG_PC &&
          scanInstr.operands[2].cls == IMM)
      {
        tableBase = scanAddr + 8 + scanInstr.operands[2].imm;
        foundTable = true;
      }

      /* Look for CMP Rx, #imm (bounds check) */
      if (maxCases == 0 && scanInstr.operation == ARMV5_CMP && scanInstr.operands[1].cls == IMM)
      {
        /* CMP Rx, #N followed by BHI/BCS means valid cases are 0..N-1 (N entries)
         * CMP Rx, #N followed by BGE/BPL means valid cases are 0..N-1 (N entries)
         * The comparison value is the first invalid case, so maxCases = imm */
        maxCases = (uint32_t)scanInstr.operands[1].imm;
        hasCmp = true;
        if (maxCases == 0)
          maxCases = 1; /* Ensure at least 1 entry */
      }

      if (foundTable && maxCases > 0)
        break;
    }

    if (!foundTable || tableBase == 0)
      return false;

    /* Default to reasonable max if no CMP found */
    if (maxCases == 0)
      maxCases = 16;
    else if (maxCases > 256)
      maxCases = 256;

    /* PC at the ADD instruction + 8 (pipeline) */
    uint64_t pcValue = jumpAddr + 8;

    /* Read the jump table and compute targets */
    uint32_t validEntries = 0;
    bool requireExecutable = view->IsOffsetExecutable(jumpAddr);
    for (uint32_t i = 0; i < maxCases; i++)
    {
      uint64_t entryAddr = tableBase + (i * 4);
      DataBuffer entryData = view->ReadBuffer(entryAddr, 4);
      if (entryData.GetLength() < 4)
        break;

      int32_t offset = *(int32_t *)entryData.GetData();

      /* Sanity check: offset should be reasonable */
      if ((offset > 0x100000) || (offset < -0x100000))
        break;
      if ((offset & 0x3) != 0)
        break;

      uint64_t target = pcValue + (int64_t)offset;
      uint64_t targetAddr = target;
      Ref<Architecture> targetArch = GetAssociatedArchitectureByAddress(targetAddr);

      if (!view->IsValidOffset(targetAddr))
        break;
      if (requireExecutable && !view->IsOffsetExecutable(targetAddr))
        break;

      targets.push_back({targetArch, targetAddr});
      validEntries++;
    }

    if (validEntries == 0)
      return false;
    if (!hasCmp && validEntries < 2)
      return false;
    return true;
  }

  bool DetectLdrPcJumpTable(BinaryView *view, uint64_t jumpAddr,
                            vector<pair<Ref<Architecture>, uint64_t>> &targets)
  {
    DataBuffer data = view->ReadBuffer(jumpAddr, 4);
    if (data.GetLength() < 4)
      return false;

    Instruction instr;
    if (!Disassemble((const uint8_t *)data.GetData(), jumpAddr, 4, instr))
      return false;

    if (instr.operation != ARMV5_LDR)
      return false;
    if (instr.operands[0].cls != REG || instr.operands[0].reg != REG_PC)
      return false;

    const InstructionOperand &memOp = instr.operands[1];
    if (memOp.cls != MEM_IMM)
      return false;
    if (memOp.reg != REG_PC)
      return false;
    if (!memOp.flags.offsetRegUsed || memOp.offset == REG_INVALID)
      return false;
    if (!memOp.flags.add)
      return false;
    if (memOp.shift != SHIFT_LSL || memOp.imm != 2)
      return false;

    uint64_t tableBase = jumpAddr + 8;
    const uint32_t maxEntries = 256;

    bool requireExecutable = view->IsOffsetExecutable(jumpAddr);
    for (uint32_t i = 0; i < maxEntries; i++)
    {
      uint64_t entryAddr = tableBase + (i * 4);
      DataBuffer entryData = view->ReadBuffer(entryAddr, 4);
      if (entryData.GetLength() < 4)
        break;

      uint32_t targetRaw = *(uint32_t *)entryData.GetData();
      uint64_t targetAddr = targetRaw;
      Ref<Architecture> targetArch = GetAssociatedArchitectureByAddress(targetAddr);
      if (!view->IsValidOffset(targetAddr))
        break;
      if (requireExecutable && !view->IsOffsetExecutable(targetAddr))
        break;

      targets.push_back({targetArch, targetAddr});
    }

    return !targets.empty();
  }

  bool DetectLdrPcLiteralTarget(BinaryView *view, uint64_t jumpAddr,
                                vector<pair<Ref<Architecture>, uint64_t>> &targets)
  {
    DataBuffer data = view->ReadBuffer(jumpAddr, 4);
    if (data.GetLength() < 4)
      return false;

    Instruction instr;
    if (!Disassemble((const uint8_t *)data.GetData(), jumpAddr, 4, instr))
      return false;

    if (instr.operation != ARMV5_LDR)
      return false;
    if (instr.operands[0].cls != REG || instr.operands[0].reg != REG_PC)
      return false;

    const InstructionOperand &memOp = instr.operands[1];
    uint64_t literalAddr = 0;
    if (memOp.cls == LABEL)
    {
      /* Disassembler pre-computes PC-relative effective address into LABEL */
      literalAddr = memOp.imm;
    }
    else
    {
      if (memOp.cls != MEM_IMM)
        return false;
      if (memOp.reg != REG_PC)
        return false;
      if (memOp.flags.offsetRegUsed)
        return false;

      literalAddr = jumpAddr + 8;
      if (memOp.flags.add)
        literalAddr += memOp.imm;
      else
        literalAddr -= memOp.imm;
    }

    DataBuffer entryData = view->ReadBuffer(literalAddr, 4);
    if (entryData.GetLength() < 4)
      return false;

    uint32_t targetRaw = *(uint32_t *)entryData.GetData();
    uint64_t targetAddr = targetRaw;
    Ref<Architecture> targetArch = GetAssociatedArchitectureByAddress(targetAddr);
    if (!view->IsValidOffset(targetAddr))
      return false;
    if (view->IsOffsetExecutable(jumpAddr) && !view->IsOffsetExecutable(targetAddr))
      return false;

    targets.push_back({targetArch, targetAddr});
    return true;
  }

  bool IsReturnThunk(BinaryView *view, uint64_t addr)
  {
    const uint32_t maxInstrs = 6;
    for (uint32_t i = 0; i < maxInstrs; i++)
    {
      uint64_t cur = addr + (i * 4);
      DataBuffer data = view->ReadBuffer(cur, 4);
      if (data.GetLength() < 4)
        return false;

      uint32_t word = *(const uint32_t *)data.GetData();
      if (word == 0xE1A00000) // NOP
        continue;

      Instruction instr;
      if (!Disassemble((const uint8_t *)data.GetData(), cur, 4, instr))
        return false;

      if (UNCONDITIONAL(instr.cond))
      {
        if (instr.operation == ARMV5_BX &&
            instr.operands[0].cls == REG && instr.operands[0].reg == REG_LR)
          return true;

        if (instr.operation == ARMV5_MOV &&
            instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC &&
            instr.operands[1].cls == REG && instr.operands[1].reg == REG_LR)
          return true;

        if (instr.operation == ARMV5_POP || instr.operation == ARMV5_LDM ||
            instr.operation == ARMV5_LDMIA || instr.operation == ARMV5_LDMIB ||
            instr.operation == ARMV5_LDMDA || instr.operation == ARMV5_LDMDB)
        {
          for (int op = 0; op < MAX_OPERANDS; op++)
          {
            if (instr.operands[op].cls == NONE)
              break;
            if (instr.operands[op].cls == REG_LIST &&
                (instr.operands[op].imm & (1U << REG_PC)))
              return true;
          }
        }
      }

      return false;
    }

    return false;
  }

  bool IsPaddingStart(BinaryView *view, uint64_t addr)
  {
    // Conservative padding detection for raw blobs:
    // - Require a run of NOPs/zeros.
    // - Require context: a preceding terminator/branch OR a following prologue.
    // - Never suppress if there's a direct call target into the gap.
    if (!view->GetCallers(addr).empty())
      return false;

    auto isPadWord = [](uint32_t word) {
      return (word == 0xE1A00000) || (word == 0x00000000);
    };

    const uint32_t maxPad = 16;
    const uint32_t minPad = 8;
    uint32_t padCount = 0;
    bool hasNonPad = false;
    uint32_t firstNonPadWord = 0;
    Instruction firstNonPadInstr{};

    for (uint32_t i = 0; i < maxPad; i++)
    {
      uint64_t cur = addr + (i * 4);
      DataBuffer data = view->ReadBuffer(cur, 4);
      if (data.GetLength() < 4)
        return false;

      uint32_t word = *(const uint32_t *)data.GetData();
      if (isPadWord(word))
      {
        padCount++;
        continue;
      }

      if (!Disassemble((const uint8_t *)data.GetData(), cur, 4, firstNonPadInstr))
        return false;
      firstNonPadWord = word;
      hasNonPad = true;
      break;
    }

    if (padCount < minPad)
      return false;

    bool prevIsTerminator = false;
    if (addr >= 4)
    {
      DataBuffer prevData = view->ReadBuffer(addr - 4, 4);
      if (prevData.GetLength() == 4)
      {
        uint32_t prevWord = *(const uint32_t *)prevData.GetData();
        if (IsFunctionEpilogue(prevWord))
          prevIsTerminator = true;

        Instruction prevInstr;
        if (!prevIsTerminator &&
            Disassemble((const uint8_t *)prevData.GetData(), addr - 4, 4, prevInstr))
        {
          if (prevInstr.operation == ARMV5_B && UNCONDITIONAL(prevInstr.cond))
            prevIsTerminator = true;
        }
      }
    }

    bool nextIsPrologue = false;
    if (hasNonPad)
    {
      if (IsFunctionPrologue(firstNonPadWord))
        nextIsPrologue = true;
    }

    // If we can't anchor the gap to a terminator or the next prologue, don't suppress it.
    if (!prevIsTerminator && !nextIsPrologue)
      return false;

    return true;
  }

  virtual void AnalyzeBasicBlocks(Function *function, BasicBlockAnalysisContext &context) override
  {
    auto data = function->GetView();
    queue<ArchAndAddr> blocksToProcess;
    map<ArchAndAddr, Ref<BasicBlock>> instrBlocks;
    set<ArchAndAddr> seenBlocks;

    bool guidedAnalysisMode = context.GetGuidedAnalysisMode();
    bool triggerGuidedOnInvalidInstruction = context.GetTriggerGuidedOnInvalidInstruction();
    bool translateTailCalls = context.GetTranslateTailCalls();
    bool disallowBranchToString = context.GetDisallowBranchToString();

    auto &indirectBranches = context.GetIndirectBranches();
    auto &indirectNoReturnCalls = context.GetIndirectNoReturnCalls();

    auto &contextualFunctionReturns = context.GetContextualReturns();

    auto &directRefs = context.GetDirectCodeReferences();
    auto &directNoReturnCalls = context.GetDirectNoReturnCalls();
    auto &haltedDisassemblyAddresses = context.GetHaltedDisassemblyAddresses();
    auto &inlinedUnresolvedIndirectBranches = context.GetInlinedUnresolvedIndirectBranches();

    auto defineLocalLabel = [&](uint64_t addr) {
      if (addr == function->GetStart())
        return;
      if (!data->IsOffsetCodeSemantics(addr))
        return;
      DataVariable dataVar;
      if (data->GetDataVariableAtAddress(addr, dataVar) && (dataVar.address == addr))
        return;
      if (!data->GetAnalysisFunctionsForAddress(addr).empty())
        return;
      if (data->GetSymbolByAddress(addr))
        return;
      size_t width = data->GetAddressSize() * 2;
      string name = fmt::format("loc_{:0{}X}", addr, width);
      data->DefineAutoSymbol(new Symbol(LocalLabelSymbol, name, addr, LocalBinding));
    };

    bool hasInvalidInstructions = false;
    set<ArchAndAddr> guidedSourceBlockTargets;
    auto guidedSourceBlocks = function->GetGuidedSourceBlocks();
    set<ArchAndAddr> guidedSourceBlocksSet;
    for (const auto &block : guidedSourceBlocks)
      guidedSourceBlocksSet.insert(block);
    set<uint64_t> loggedUnresolvedIndirect;

    BNStringReference strRef;
    auto targetExceedsByteLimit = [](const BNStringReference &strRef)
    {
      size_t byteLimit = 8;
      if (strRef.type == Utf16String)
        byteLimit *= 2;
      else if (strRef.type == Utf32String)
        byteLimit *= 4;
      return (strRef.length >= byteLimit);
    };

    Ref<Platform> funcPlatform = function->GetPlatform();
    auto start = function->GetStart();
    blocksToProcess.emplace(funcPlatform->GetArchitecture(), start);
    seenBlocks.emplace(funcPlatform->GetArchitecture(), start);

    bool validateExecutable = data->IsOffsetExecutable(start);

    bool fastValidate = false;
    uint64_t fastEndAddr = 0;
    uint64_t fastStartAddr = UINT64_MAX;
    if (validateExecutable)
    {
      for (auto &sec : data->GetSectionsAt(start))
      {
        if (sec->GetSemantics() == ReadOnlyDataSectionSemantics)
          continue;
        if (sec->GetSemantics() == ReadWriteDataSectionSemantics)
          continue;
        if (!data->IsOffsetBackedByFile(sec->GetStart()))
          continue;
        if (!data->IsOffsetExecutable(sec->GetStart()))
          continue;
        if (fastStartAddr > sec->GetStart())
          fastStartAddr = sec->GetStart();
        if (fastEndAddr < (sec->GetEnd() - 1))
        {
          fastEndAddr = sec->GetEnd() - 1;
          Ref<Segment> segment = data->GetSegmentAt(fastEndAddr);
          if (segment)
            fastEndAddr = (std::min)(fastEndAddr, segment->GetDataEnd() - 1);
        }
        fastValidate = true;
        break;
      }
    }

    uint64_t totalSize = 0;
    uint64_t maxSize = context.GetMaxFunctionSize();
    bool maxSizeReached = false;

    while (blocksToProcess.size() != 0)
    {
      if (data->AnalysisIsAborted())
        return;

      ArchAndAddr location = blocksToProcess.front();
      ArchAndAddr instructionGroupStart = location;
      blocksToProcess.pop();

      bool isGuidedSourceBlock = guidedSourceBlocksSet.count(location) ? true : false;

      Ref<BasicBlock> block = context.CreateBasicBlock(location.arch, location.address);

      if ((location.address == function->GetStart()) && IsPaddingStart(data, location.address))
      {
        // Avoid creating functions on alignment padding between real function bodies.
        string text = fmt::format("Padding/alignment at {:#x}", location.address);
        function->CreateAutoAddressTag(location.arch, location.address, "Padding", text, true);
        context.Finalize();
        return;
      }

      Ref<Function> nextFunc;
      bool hasNextFunc = GetNextFunctionAfterAddress(data, funcPlatform, location.address, nextFunc);
      uint64_t nextFuncAddr = (hasNextFunc && nextFunc) ? nextFunc->GetStart() : 0;
      set<Ref<Function>> calledFunctions;

      uint8_t delaySlotCount = 0;
      bool delayInstructionEndsBlock = false;

      while (true)
      {
        if (data->AnalysisIsAborted())
          return;

        DataVariable dataVar;
        if (data->GetDataVariableAtAddress(location.address, dataVar) &&
            (dataVar.address == location.address) && (location.address != function->GetStart()))
        {
          bool smallAutoData = false;
          if (dataVar.type.GetValue())
          {
            uint64_t width = dataVar.type.GetValue()->GetWidth();
            smallAutoData = (width <= 1);
          }
          bool canRecover =
              dataVar.autoDiscovered && (smallAutoData || !dataVar.type.GetValue()) &&
              data->IsOffsetCodeSemantics(location.address) &&
              (location.address - function->GetStart() <= 0x40);
          if (canRecover)
          {
            uint8_t probe[BN_MAX_INSTRUCTION_LENGTH];
            size_t probeLen = data->Read(probe, location.address, location.arch->GetMaxInstructionLength());
            InstructionInfo probeInfo;
            if (probeLen && location.arch->GetInstructionInfo(probe, location.address, probeLen, probeInfo) &&
                probeInfo.length > 0)
            {
              uint64_t nextAddr = location.address + probeInfo.length;
              uint8_t probeNext[BN_MAX_INSTRUCTION_LENGTH];
              size_t probeNextLen = data->Read(probeNext, nextAddr, location.arch->GetMaxInstructionLength());
              InstructionInfo probeNextInfo;
              if (probeNextLen &&
                  location.arch->GetInstructionInfo(probeNext, nextAddr, probeNextLen, probeNextInfo) &&
                  probeNextInfo.length > 0)
              {
                data->UndefineDataVariable(location.address, true);
                continue;
              }
            }
          }

          // Stop at typed data (literal pools) or non-code bytes.
          break;
        }

        if (!delaySlotCount)
        {
          auto blockIter = instrBlocks.find(location);
          if (blockIter != instrBlocks.end())
          {
            Ref<BasicBlock> targetBlock = blockIter->second;
            if (targetBlock->GetStart() == location.address)
            {
              block->AddPendingOutgoingEdge(UnconditionalBranch, location.address, nullptr,
                                            (block->GetStart() != location.address));
              break;
            }
            else
            {
              Ref<BasicBlock> splitBlock = context.CreateBasicBlock(location.arch, location.address);
              size_t instrDataLen;
              const uint8_t *instrData = targetBlock->GetInstructionData(location.address, &instrDataLen);
              splitBlock->AddInstructionData(instrData, instrDataLen);
              splitBlock->SetFallThroughToFunction(targetBlock->IsFallThroughToFunction());
              splitBlock->SetUndeterminedOutgoingEdges(targetBlock->HasUndeterminedOutgoingEdges());
              splitBlock->SetCanExit(targetBlock->CanExit());
              splitBlock->SetEnd(targetBlock->GetEnd());

              targetBlock->SetFallThroughToFunction(false);
              targetBlock->SetUndeterminedOutgoingEdges(false);
              targetBlock->SetCanExit(true);
              targetBlock->SetEnd(location.address);

              for (size_t j = location.address; j < splitBlock->GetEnd(); j++)
              {
                auto k = instrBlocks.find(ArchAndAddr(location.arch, j));
                if ((k != instrBlocks.end()) && (k->second == targetBlock))
                  k->second = splitBlock;
              }

              for (auto &k : targetBlock->GetPendingOutgoingEdges())
                splitBlock->AddPendingOutgoingEdge(k.type, k.target, k.arch, k.fallThrough);
              targetBlock->ClearPendingOutgoingEdges();
              targetBlock->AddPendingOutgoingEdge(UnconditionalBranch, location.address, nullptr, true);

              seenBlocks.insert(location);
              defineLocalLabel(location.address);
              context.AddFunctionBasicBlock(splitBlock);

              block->AddPendingOutgoingEdge(UnconditionalBranch, location.address);
              break;
            }
          }
        }

        uint8_t opcode[BN_MAX_INSTRUCTION_LENGTH];
        size_t maxLen = data->Read(opcode, location.address, location.arch->GetMaxInstructionLength());
        if (maxLen == 0)
        {
          string text = fmt::format("Could not read instruction at {:#x}", location.address);
          function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
          if (location.arch->GetInstructionAlignment() == 0)
            location.address++;
          else
            location.address += location.arch->GetInstructionAlignment();
          block->SetHasInvalidInstructions(true);
          break;
        }

        InstructionInfo info;
        info.delaySlots = delaySlotCount;
        if (!location.arch->GetInstructionInfo(opcode, location.address, maxLen, info))
        {
          string text = fmt::format("Could not get instruction info at {:#x}", location.address);
          function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
          if (location.arch->GetInstructionAlignment() == 0)
            location.address++;
          else
            location.address += location.arch->GetInstructionAlignment();
          block->SetHasInvalidInstructions(true);
          break;
        }

        if ((info.length == 0) || (info.length > maxLen))
        {
          string text = fmt::format("Instruction of invalid length at {:#x}", location.address);
          function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
          if (location.arch->GetInstructionAlignment() == 0)
            location.address++;
          else
            location.address += location.arch->GetInstructionAlignment();
          block->SetHasInvalidInstructions(true);
          break;
        }

        uint64_t instrEnd = location.address + info.length - 1;
        bool slowPath = !fastValidate || (instrEnd < fastStartAddr) || (instrEnd > fastEndAddr);
        if (slowPath &&
            ((!data->IsOffsetCodeSemantics(instrEnd) && data->IsOffsetCodeSemantics(location.address)) ||
             (!data->IsOffsetBackedByFile(instrEnd) && data->IsOffsetBackedByFile(location.address))))
        {
          string text = fmt::format("Instruction at {:#x} straddles a non-code section", location.address);
          function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
          if (location.arch->GetInstructionAlignment() == 0)
            location.address++;
          else
            location.address += location.arch->GetInstructionAlignment();
          block->SetHasInvalidInstructions(true);
          break;
        }

        bool endsBlock = false;
        ArchAndAddr target;
        map<ArchAndAddr, set<ArchAndAddr>>::const_iterator indirectBranchIter, endIter;
        if (!delaySlotCount)
        {
          instrBlocks[location] = block;
          instructionGroupStart = location;

          for (size_t i = 0; i < info.branchCount; i++)
          {
            bool fastPath;

            auto handleAsFallback = [&]()
            {
              endsBlock = true;

              bool callLikeIndirect = false;
              if (info.branchType[i] == IndirectBranch || info.branchType[i] == UnresolvedBranch)
              {
                Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(location.arch, nullptr);
                ilFunc->SetCurrentAddress(location.arch, location.address);
                location.arch->GetInstructionLowLevelIL(opcode, location.address, maxLen, *ilFunc);
                for (size_t idx = 0; idx < ilFunc->GetInstructionCount(); idx++)
                {
                  if ((*ilFunc)[idx].operation == LLIL_CALL)
                  {
                    callLikeIndirect = true;
                    endsBlock = false;
                    break;
                  }
                  if ((*ilFunc)[idx].operation == LLIL_TAILCALL)
                  {
                    callLikeIndirect = true;
                    break;
                  }
                }
              }

              /*
               * Heuristic: treat "MOV/ADD LR, PC; LDR PC, [Rn, #imm]" as an indirect call.
               *
               * Rationale:
               * - On ARMv5, compilers often synthesize a call through a function pointer
               *   (vtable/dispatch) using:
               *       mov lr, pc
               *       ldr pc, [rX, #imm]
               * - Semantically this behaves like BLX/BL: LR is set to the return address
               *   and control returns to the next instruction after the LDR.
               * - We cannot resolve the target statically, but we can avoid logging it as
               *   "unresolved indirect control flow" because it is a normal callsite.
               *
               * Implementation notes:
               * - Only apply in ARM mode (4-byte instructions).
               * - Confirm the current instruction is an LDR into PC.
               * - Look back one instruction for LR being set from PC (MOV or ADD #imm).
               * - If matched, mark as call-like and allow fallthrough (endsBlock = false).
               */
              if (!callLikeIndirect && (info.branchType[i] == IndirectBranch || info.branchType[i] == UnresolvedBranch) &&
                  (info.length == 4) && (location.address >= 4))
              {
                Instruction curInstr{};
                uint32_t bigEndian = (location.arch->GetEndianness() == BigEndian);
                if (armv5_decompose(*(uint32_t *)opcode, &curInstr, (uint32_t)location.address, bigEndian) == 0)
                {
                  bool isLdrPc =
                      (curInstr.operation == ARMV5_LDR) &&
                      (curInstr.operands[0].cls == REG) &&
                      (curInstr.operands[0].reg == REG_PC);

                  if (isLdrPc)
                  {
                    DataBuffer prevData = data->ReadBuffer(location.address - 4, 4);
                    if (prevData.GetLength() == 4)
                    {
                      Instruction prevInstr{};
                      if (armv5_decompose(*(uint32_t *)prevData.GetData(), &prevInstr,
                                          (uint32_t)(location.address - 4), bigEndian) == 0)
                      {
                        bool movLrPc =
                            (prevInstr.operation == ARMV5_MOV) &&
                            (prevInstr.operands[0].cls == REG) &&
                            (prevInstr.operands[0].reg == REG_LR) &&
                            (prevInstr.operands[1].cls == REG) &&
                            (prevInstr.operands[1].reg == REG_PC);

                        bool addLrPcImm =
                            (prevInstr.operation == ARMV5_ADD) &&
                            (prevInstr.operands[0].cls == REG) &&
                            (prevInstr.operands[0].reg == REG_LR) &&
                            (prevInstr.operands[1].cls == REG) &&
                            (prevInstr.operands[1].reg == REG_PC) &&
                            (prevInstr.operands[2].cls == IMM);

                        if (movLrPc || addLrPcImm)
                        {
                          callLikeIndirect = true;
                          endsBlock = false;
                        }
                      }
                    }
                  }
                }
              }

              set<ArchAndAddr> resolvedTargets;
              indirectBranchIter = indirectBranches.find(location);
              endIter = indirectBranches.end();
              if (indirectBranchIter != endIter)
              {
                for (auto &branch : indirectBranchIter->second)
                  resolvedTargets.insert(branch);
              }
              else if (info.branchType[i] == IndirectBranch || info.branchType[i] == UnresolvedBranch)
              {
                vector<pair<Ref<Architecture>, uint64_t>> jumpTableTargets;
                DetectSwitchTable(data, location.address, jumpTableTargets);
                DetectLdrPcJumpTable(data, location.address, jumpTableTargets);
                DetectLdrPcLiteralTarget(data, location.address, jumpTableTargets);
                for (auto &branch : jumpTableTargets)
                {
                  Ref<Architecture> targetArch = branch.first ? branch.first : location.arch;
                  resolvedTargets.emplace(targetArch, branch.second);
                }
              }

              if (!resolvedTargets.empty())
              {
                for (auto &branch : resolvedTargets)
                {
                  directRefs[branch.address].emplace(location);
                  Ref<Platform> targetPlatform = funcPlatform;
                  if (branch.arch != function->GetArchitecture())
                    targetPlatform = funcPlatform->GetRelatedPlatform(branch.arch);

                  if (translateTailCalls && targetPlatform &&
                      data->GetAnalysisFunction(targetPlatform, branch.address))
                    continue;

                if (isGuidedSourceBlock)
                  guidedSourceBlockTargets.insert(branch);

                defineLocalLabel(branch.address);
                block->AddPendingOutgoingEdge(IndirectBranch, branch.address, branch.arch);
                if (seenBlocks.count(branch) == 0)
                {
                  blocksToProcess.push(branch);
                  seenBlocks.insert(branch);
                  }
                }
              }
              else if (info.branchType[i] == ExceptionBranch)
              {
                block->SetCanExit(false);
              }
              else if (info.branchType[i] == FunctionReturn && function->CanReturn().GetValue())
              {
                auto it = contextualFunctionReturns.find(location);
                if (it != contextualFunctionReturns.end())
                {
                  endsBlock = it->second;
                }
                else
                {
                  Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(location.arch, nullptr);
                  ilFunc->SetCurrentAddress(location.arch, location.address);
                  location.arch->GetInstructionLowLevelIL(opcode, location.address, maxLen, *ilFunc);
                  if (ilFunc->GetInstructionCount() && ((*ilFunc)[0].operation == LLIL_CALL))
                    contextualFunctionReturns[location] = false;
                  else
                    contextualFunctionReturns[location] = true;
                  endsBlock = contextualFunctionReturns[location];
                }
              }
              else
              {
                if ((info.branchType[i] == IndirectBranch || info.branchType[i] == UnresolvedBranch) &&
                    !callLikeIndirect && resolvedTargets.empty() &&
                    (loggedUnresolvedIndirect.count(location.address) == 0))
                {
                  loggedUnresolvedIndirect.insert(location.address);
                  BNLogInfo("Unresolved indirect control flow at 0x%" PRIx64 " in function 0x%" PRIx64,
                            location.address, function->GetStart());
                }
                block->SetUndeterminedOutgoingEdges(true);
              }
            };

            switch (info.branchType[i])
            {
            case UnconditionalBranch:
            case TrueBranch:
            case FalseBranch:
              endsBlock = true;
              if (data->IsOffsetExternSemantics(info.branchTarget[i]))
              {
                DataVariable dataVar;
                if (data->GetDataVariableAtAddress(info.branchTarget[i], dataVar) &&
                    (dataVar.address == info.branchTarget[i]) && dataVar.type.GetValue() &&
                    (dataVar.type->GetClass() == FunctionTypeClass))
                {
                  directRefs[info.branchTarget[i]].emplace(location);
                  if (!dataVar.type->CanReturn())
                  {
                    directNoReturnCalls.insert(location);
                    endsBlock = true;
                    block->SetCanExit(false);
                  }
                }
                break;
              }

              if (data->IsValidOffset(info.branchTarget[i]) && IsReturnThunk(data, info.branchTarget[i]))
              {
                endsBlock = true;
                block->SetCanExit(true);
                break;
              }

              fastPath = fastValidate && (info.branchTarget[i] >= fastStartAddr) &&
                         (info.branchTarget[i] <= fastEndAddr);
              if (fastPath ||
                  (data->IsValidOffset(info.branchTarget[i]) &&
                   data->IsOffsetBackedByFile(info.branchTarget[i]) &&
                   ((!validateExecutable) || data->IsOffsetExecutable(info.branchTarget[i]))))
              {
                target = ArchAndAddr(info.branchArch[i] ? new CoreArchitecture(info.branchArch[i]) : location.arch,
                                     info.branchTarget[i]);

                if (data->ShouldSkipTargetAnalysis(location, function, instrEnd, target))
                  break;

                Ref<Platform> targetPlatform = funcPlatform;
                if (target.arch != funcPlatform->GetArchitecture())
                  targetPlatform = funcPlatform->GetRelatedPlatform(target.arch);

                directRefs[info.branchTarget[i]].insert(location);

                if (translateTailCalls && (info.branchType[i] == UnconditionalBranch) &&
                    (target.address < function->GetStart()))
                {
                  Ref<Function> forcedFunc = data->AddFunctionForAnalysis(targetPlatform, target.address, true);
                  if (forcedFunc)
                  {
                    context.AddTempOutgoingReference(forcedFunc);
                    calledFunctions.insert(forcedFunc);
                    if (!forcedFunc->CanReturn() && !forcedFunc->IsInlinedDuringAnalysis().GetValue())
                    {
                      directNoReturnCalls.insert(location);
                      endsBlock = true;
                      block->SetCanExit(false);
                    }
                    break;
                  }
                }

                auto otherFunc = function->GetCalleeForAnalysis(targetPlatform, target.address, true);
                if (translateTailCalls && targetPlatform && otherFunc && (otherFunc->GetStart() != function->GetStart()))
                {
                  calledFunctions.insert(otherFunc);
                  if (info.branchType[i] == UnconditionalBranch)
                  {
                    if (!otherFunc->CanReturn() && !otherFunc->IsInlinedDuringAnalysis().GetValue())
                    {
                      directNoReturnCalls.insert(location);
                      endsBlock = true;
                      block->SetCanExit(false);
                    }
                    break;
                  }
                }
                else if (disallowBranchToString && data->GetStringAtAddress(target.address, strRef) &&
                         targetExceedsByteLimit(strRef))
                {
                  BNLogInfo("Not adding branch target from 0x%" PRIx64 " to string at 0x%" PRIx64 " length:%zu",
                            location.address, target.address, strRef.length);
                  break;
                }
                else
                {
                  if (isGuidedSourceBlock)
                    guidedSourceBlockTargets.insert(target);

                  if (info.branchType[i] != FalseBranch)
                    defineLocalLabel(target.address);
                  block->AddPendingOutgoingEdge(info.branchType[i], target.address, target.arch);
                  if (seenBlocks.count(target) == 0)
                  {
                    blocksToProcess.push(target);
                    seenBlocks.insert(target);
                  }
                }
              }
              break;

            case CallDestination:
              if (data->IsOffsetExternSemantics(info.branchTarget[i]))
              {
                DataVariable dataVar;
                if (data->GetDataVariableAtAddress(info.branchTarget[i], dataVar) &&
                    (dataVar.address == info.branchTarget[i]) && dataVar.type.GetValue() &&
                    (dataVar.type->GetClass() == FunctionTypeClass))
                {
                  directRefs[info.branchTarget[i]].emplace(location);
                  if (!dataVar.type->CanReturn())
                  {
                    directNoReturnCalls.insert(location);
                    endsBlock = true;
                    block->SetCanExit(false);
                  }
                }
                break;
              }

              fastPath = fastValidate && (info.branchTarget[i] >= fastStartAddr) &&
                         (info.branchTarget[i] <= fastEndAddr);
              if (fastPath ||
                  (data->IsValidOffset(info.branchTarget[i]) && data->IsOffsetBackedByFile(info.branchTarget[i]) &&
                   ((!validateExecutable) || data->IsOffsetExecutable(info.branchTarget[i]))))
              {
                target = ArchAndAddr(info.branchArch[i] ? new CoreArchitecture(info.branchArch[i]) : location.arch,
                                     info.branchTarget[i]);

                if (!fastPath && !data->IsOffsetCodeSemantics(target.address) &&
                    data->IsOffsetCodeSemantics(location.address))
                {
                  string message = fmt::format("Non-code call target {:#x}", target.address);
                  function->CreateAutoAddressTag(target.arch, location.address, "Non-code Branch", message, true);
                  break;
                }

                Ref<Platform> platform = funcPlatform;
                if (target.arch != platform->GetArchitecture())
                {
                  platform = funcPlatform->GetRelatedPlatform(target.arch);
                  if (!platform)
                    platform = funcPlatform;
                }

                if (data->ShouldSkipTargetAnalysis(location, function, instrEnd, target))
                  break;

                Ref<Function> func = data->AddFunctionForAnalysis(platform, target.address, true);
                if (!func)
                {
                  if (!data->IsOffsetBackedByFile(target.address))
                    BNLogError("Function at 0x%" PRIx64 " failed to add target not backed by file.",
                               function->GetStart());
                  break;
                }

                context.AddTempOutgoingReference(func);
                calledFunctions.emplace(func);
                directRefs[target.address].emplace(location);
                if (!func->CanReturn())
                {
                  if (func->IsInlinedDuringAnalysis().GetValue() && func->HasUnresolvedIndirectBranches())
                  {
                    auto unresolved = func->GetUnresolvedIndirectBranches();
                    if (unresolved.size() == 1)
                    {
                      inlinedUnresolvedIndirectBranches[location] = *unresolved.begin();
                      handleAsFallback();
                      break;
                    }
                  }

                  directNoReturnCalls.insert(location);
                  endsBlock = true;
                  block->SetCanExit(false);
                }
              }
              break;

            case SystemCall:
              break;

            default:
              handleAsFallback();
              break;
            }
          }
        }

        if (indirectNoReturnCalls.count(location))
        {
          size_t instrLength = info.length;
          if (info.delaySlots)
          {
            InstructionInfo delayInfo;
            delayInfo.delaySlots = info.delaySlots;
            size_t archMax = location.arch->GetMaxInstructionLength();
            uint8_t delayOpcode[BN_MAX_INSTRUCTION_LENGTH];
            do
            {
              delayInfo.delaySlots--;
              if (!location.arch->GetInstructionInfo(delayOpcode, location.address + instrLength,
                                                     archMax - instrLength, delayInfo))
                break;
              instrLength += delayInfo.length;
            } while (delayInfo.delaySlots && (instrLength < archMax));
          }

          Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(location.arch, nullptr);
          ilFunc->SetCurrentAddress(location.arch, location.address);
          location.arch->GetInstructionLowLevelIL(opcode, location.address, maxLen, *ilFunc);
          if (!(ilFunc->GetInstructionCount() && ((*ilFunc)[0].operation == LLIL_IF)))
          {
            endsBlock = true;
            block->SetCanExit(false);
          }
        }

        location.address += info.length;
        block->AddInstructionData(opcode, info.length);

        if (endsBlock && !info.delaySlots)
          break;

        totalSize += info.length;
        auto analysisSkipOverride = context.GetAnalysisSkipOverride();
        if (analysisSkipOverride == NeverSkipFunctionAnalysis)
          maxSize = 0;
        else if (!maxSize && (analysisSkipOverride == AlwaysSkipFunctionAnalysis))
          maxSize = context.GetMaxFunctionSize();

        if (maxSize && (totalSize > maxSize))
        {
          maxSizeReached = true;
          break;
        }

        if (delaySlotCount)
        {
          delaySlotCount--;
          if (!delaySlotCount && delayInstructionEndsBlock)
            break;
        }
        else
        {
          delaySlotCount = info.delaySlots;
          delayInstructionEndsBlock = endsBlock;
        }

        if (block->CanExit() && translateTailCalls && !delaySlotCount && hasNextFunc &&
            (location.address == nextFuncAddr))
        {
          if (calledFunctions.count(nextFunc) == 0)
          {
            block->SetFallThroughToFunction(true);
            if (!nextFunc->CanReturn())
            {
              directNoReturnCalls.insert(instructionGroupStart);
              block->SetCanExit(false);
            }
            break;
          }
          hasNextFunc = GetNextFunctionAfterAddress(data, funcPlatform, location.address, nextFunc);
          nextFuncAddr = (hasNextFunc && nextFunc) ? nextFunc->GetStart() : 0;
        }
      }

      if (location.address != block->GetStart())
      {
        block->SetEnd(location.address);
        context.AddFunctionBasicBlock(block);
      }

      if (maxSizeReached)
        break;

      if (triggerGuidedOnInvalidInstruction && block->HasInvalidInstructions())
        hasInvalidInstructions = true;

      if (guidedAnalysisMode || hasInvalidInstructions || guidedSourceBlocksSet.size())
      {
        queue<ArchAndAddr> guidedBlocksToProcess;
        while (!blocksToProcess.empty())
        {
          auto i = blocksToProcess.front();
          blocksToProcess.pop();
          if (guidedSourceBlockTargets.count(i))
            guidedBlocksToProcess.emplace(i);
          else
            haltedDisassemblyAddresses.emplace(i);
        }
        blocksToProcess = guidedBlocksToProcess;
      }
    }

    if (maxSizeReached)
      context.SetMaxSizeReached(true);

    context.Finalize();
  }
};

/*
 * ArmCommonArchitecture Implementation
 */
ArmCommonArchitecture::ArmCommonArchitecture(const char *name, BNEndianness endian) : Architecture(name), m_endian(endian)
{
}

void ArmCommonArchitecture::SetArmAndThumbArchitectures(Architecture *arm, Architecture *thumb)
{
  m_armArch = arm;
  m_thumbArch = thumb;
}

/*
 * ArmCommonArchitecture base class method implementations
 * (ThumbArchitecture is now in thumb_disasm/arch_thumb.cpp)
 */

Ref<Architecture> ArmCommonArchitecture::GetAssociatedArchitectureByAddress(uint64_t &addr)
{
  if (addr & 1)
  {
    addr &= ~1LL;
    /*
     * Don't return Thumb architecture for very low addresses.
     * The ARM vector table at 0x00-0x1C should always be ARM mode.
     * Pointer sweep may find small integer values (1, 3, 5, 7, etc.) in data
     * sections that happen to look like "Thumb address" but aren't actually
     * function pointers. This prevents spurious Thumb function creation in
     * the vector table region.
     */
    if (addr < 0x20)
      return m_armArch;
    return m_thumbArch;
  }
  return m_armArch;
}

BNEndianness ArmCommonArchitecture::GetEndianness() const
{
  return m_endian;
}

size_t ArmCommonArchitecture::GetAddressSize() const
{
  return 4;
}

string ArmCommonArchitecture::GetFlagName(uint32_t flag)
{
  char result[32];
  switch (flag)
  {
  case IL_FLAG_N:
    return "n";
  case IL_FLAG_Z:
    return "z";
  case IL_FLAG_C:
    return "c";
  case IL_FLAG_V:
    return "v";
  case IL_FLAG_Q:
    return "q";
  default:
    snprintf(result, sizeof(result), "flag%" PRIu32, flag);
    return result;
  }
}

string ArmCommonArchitecture::GetFlagWriteTypeName(uint32_t flags)
{
  switch (flags)
  {
  case IL_FLAGWRITE_ALL:
    return "*";
  case IL_FLAGWRITE_NZ:
    return "nz";
  case IL_FLAGWRITE_CNZ:
    return "cnz";
  case IL_FLAGWRITE_NZC:
    return "nzc";
  case IL_FLAGWRITE_NZCV:
    return "nzcv";
  default:
    return "";
  }
}

BNFlagRole ArmCommonArchitecture::GetFlagRole(uint32_t flag, uint32_t)
{
  switch (flag)
  {
  case IL_FLAG_N:
    return NegativeSignFlagRole;
  case IL_FLAG_Z:
    return ZeroFlagRole;
  case IL_FLAG_C:
    return CarryFlagRole;
  case IL_FLAG_V:
    return OverflowFlagRole;
  default:
    return SpecialFlagRole;
  }
}

vector<uint32_t> ArmCommonArchitecture::GetFlagsWrittenByFlagWriteType(uint32_t flags)
{
  switch (flags)
  {
  case IL_FLAGWRITE_ALL:
  case IL_FLAGWRITE_NZCV:
    return vector<uint32_t>{IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C, IL_FLAG_V};
  case IL_FLAGWRITE_NZ:
    return vector<uint32_t>{IL_FLAG_N, IL_FLAG_Z};
  case IL_FLAGWRITE_CNZ:
    return vector<uint32_t>{IL_FLAG_C, IL_FLAG_N, IL_FLAG_Z};
  case IL_FLAGWRITE_NZC:
    return vector<uint32_t>{IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C};
  default:
    return vector<uint32_t>{};
  }
}

vector<uint32_t> ArmCommonArchitecture::GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t)
{
  switch (cond)
  {
  case LLFC_E:
  case LLFC_NE:
    return vector<uint32_t>{IL_FLAG_Z};
  case LLFC_SLT:
  case LLFC_SGE:
    return vector<uint32_t>{IL_FLAG_N, IL_FLAG_V};
  case LLFC_ULT:
  case LLFC_UGE:
    return vector<uint32_t>{IL_FLAG_C};
  case LLFC_SLE:
  case LLFC_SGT:
    return vector<uint32_t>{IL_FLAG_Z, IL_FLAG_N, IL_FLAG_V};
  case LLFC_ULE:
  case LLFC_UGT:
    return vector<uint32_t>{IL_FLAG_C, IL_FLAG_Z};
  case LLFC_NEG:
  case LLFC_POS:
    return vector<uint32_t>{IL_FLAG_N};
  case LLFC_O:
  case LLFC_NO:
    return vector<uint32_t>{IL_FLAG_V};
  default:
    return vector<uint32_t>{};
  }
}

size_t ArmCommonArchitecture::GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
                                                     uint32_t flag, BNRegisterOrConstant *operands, size_t operandCount, LowLevelILFunction &il)
{
  switch (op)
  {
  case LLIL_SBB:
    switch (flag)
    {
    case IL_FLAG_C:
      // r u< a || (r == a && flag_c)
      return il.Or(0,
                   il.CompareUnsignedLessThan(size,
                                              il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
                                              il.GetExprForRegisterOrConstant(operands[0], size)),
                   il.And(0,
                          il.CompareEqual(size,
                                          il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
                                          il.GetExprForRegisterOrConstant(operands[0], size)),
                          il.Flag(IL_FLAG_C)));
    case IL_FLAG_V:
      return il.CompareEqual(0,
                             il.CompareSignedLessThan(size,
                                                      il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
                                                      il.GetExprForRegisterOrConstant(operands[0], size)),
                             il.CompareEqual(size,
                                             il.GetExprForRegisterOrConstant(operands[0], size),
                                             il.Const(size, 0)));
    }
    break;
  case LLIL_LSR:
    switch (flag)
    {
    case IL_FLAG_C:
      return il.TestBit(0,
                        il.GetExprForRegisterOrConstant(operands[0], size),
                        il.Sub(size, il.GetExprForRegisterOrConstant(operands[1], size), il.Const(size, 1)));
    }
    break;
  case LLIL_LSL:
    switch (flag)
    {
    case IL_FLAG_C:
      return il.TestBit(0,
                        il.GetExprForRegisterOrConstant(operands[0], size),
                        il.Sub(size, il.Const(size, 8 * size), il.GetExprForRegisterOrConstant(operands[1], size)));
    }
  default:
    break;
  }

  BNFlagRole role = GetFlagRole(flag, GetSemanticClassForFlagWriteType(flagWriteType));
  return GetDefaultFlagWriteLowLevelIL(op, size, role, operands, operandCount, il);
}

string ArmCommonArchitecture::GetRegisterName(uint32_t reg)
{
  if (reg >= REG_R0 && reg < REG_INVALID)
  {
    return get_register_name((enum Register)reg);
  }

  //LogError("Unknown Register: %x - Please report this as a bug.\n", reg);
  return "unknown";
}

vector<uint32_t> ArmCommonArchitecture::GetFullWidthRegisters()
{
  return vector<uint32_t>{
      REG_R0,
      REG_R1,
      REG_R2,
      REG_R3,
      REG_R4,
      REG_R5,
      REG_R6,
      REG_R7,
      REG_R8,
      REG_R9,
      REG_R10,
      REG_R11,
      REG_R12,
      REG_R13,
      REG_R14,
      REG_R15,
      REG_D0,
      REG_D1,
      REG_D2,
      REG_D3,
      REG_D4,
      REG_D5,
      REG_D6,
      REG_D7,
      REG_D8,
      REG_D9,
      REG_D10,
      REG_D11,
      REG_D12,
      REG_D13,
      REG_D14,
      REG_D15,
  };
}

vector<uint32_t> ArmCommonArchitecture::GetAllRegisters()
{
  return vector<uint32_t>{
      REG_R0,
      REG_R1,
      REG_R2,
      REG_R3,
      REG_R4,
      REG_R5,
      REG_R6,
      REG_R7,
      REG_R8,
      REG_R9,
      REG_R10,
      REG_R11,
      REG_R12,
      REG_R13,
      REG_R14,
      REG_R15,
      REG_S0,
      REG_S1,
      REG_S2,
      REG_S3,
      REG_S4,
      REG_S5,
      REG_S6,
      REG_S7,
      REG_S8,
      REG_S9,
      REG_S10,
      REG_S11,
      REG_S12,
      REG_S13,
      REG_S14,
      REG_S15,
      REG_S16,
      REG_S17,
      REG_S18,
      REG_S19,
      REG_S20,
      REG_S21,
      REG_S22,
      REG_S23,
      REG_S24,
      REG_S25,
      REG_S26,
      REG_S27,
      REG_S28,
      REG_S29,
      REG_S30,
      REG_S31,
      REG_D0,
      REG_D1,
      REG_D2,
      REG_D3,
      REG_D4,
      REG_D5,
      REG_D6,
      REG_D7,
      REG_D8,
      REG_D9,
      REG_D10,
      REG_D11,
      REG_D12,
      REG_D13,
      REG_D14,
      REG_D15,

      /* special registers */
      REGS_FPSID,
      REGS_FPSCR,
      REGS_FPEXC,
  };
}

vector<uint32_t> ArmCommonArchitecture::GetAllFlags()
{
  return vector<uint32_t>{
      IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C, IL_FLAG_V, IL_FLAG_Q};
}

vector<uint32_t> ArmCommonArchitecture::GetAllFlagWriteTypes()
{
  return vector<uint32_t>{
      IL_FLAGWRITE_ALL,
      IL_FLAGWRITE_NZ,
      IL_FLAGWRITE_CNZ,
      IL_FLAGWRITE_NZC,
      IL_FLAGWRITE_NZCV};
}

BNRegisterInfo ArmCommonArchitecture::GetRegisterInfo(uint32_t reg)
{
  switch (reg)
  {
  case REG_R0:
  case REG_R1:
  case REG_R2:
  case REG_R3:
  case REG_R4:
  case REG_R5:
  case REG_R6:
  case REG_R7:
  case REG_R8:
  case REG_R9:
  case REG_R10:
  case REG_R11:
  case REG_R12:
  case REG_R13:
  case REG_R14:
  case REG_R15:
    return RegisterInfo(reg, 0, 4);
  case REG_S0:
  case REG_S1:
  case REG_S2:
  case REG_S3:
  case REG_S4:
  case REG_S5:
  case REG_S6:
  case REG_S7:
  case REG_S8:
  case REG_S9:
  case REG_S10:
  case REG_S11:
  case REG_S12:
  case REG_S13:
  case REG_S14:
  case REG_S15:
  case REG_S16:
  case REG_S17:
  case REG_S18:
  case REG_S19:
  case REG_S20:
  case REG_S21:
  case REG_S22:
  case REG_S23:
  case REG_S24:
  case REG_S25:
  case REG_S26:
  case REG_S27:
  case REG_S28:
  case REG_S29:
  case REG_S30:
  case REG_S31:
    return RegisterInfo(REG_D0 + ((reg - REG_S0) / 2), ((reg - REG_S0) % 2) * 4, 4);
  case REG_D0:
  case REG_D1:
  case REG_D2:
  case REG_D3:
  case REG_D4:
  case REG_D5:
  case REG_D6:
  case REG_D7:
  case REG_D8:
  case REG_D9:
  case REG_D10:
  case REG_D11:
  case REG_D12:
  case REG_D13:
  case REG_D14:
  case REG_D15:
    return RegisterInfo(reg, 0, 8);
  default:
    return RegisterInfo(reg, 0, 4);
  }
}

uint32_t ArmCommonArchitecture::GetStackPointerRegister()
{
  return REG_SP;
}

uint32_t ArmCommonArchitecture::GetLinkRegister()
{
  return REG_LR;
}
bool ArmCommonArchitecture::CanAssemble()
{
  return true;
}

bool ArmCommonArchitecture::Assemble(const string &code, uint64_t addr, DataBuffer &result, string &errors)
{
  (void)addr;

  char *instrBytes = NULL, *err = NULL;
  int instrBytesLen = 0, errLen = 0;

  int assembleResult;

  string triple = GetAssemblerTriple();
  LogDebug("%s() retrieves and uses triple %s\n", __func__, triple.c_str());

  BNLlvmServicesInit();

  errors.clear();
  assembleResult = BNLlvmServicesAssemble(code.c_str(), LLVM_SVCS_DIALECT_UNSPEC,
                                          triple.c_str(), LLVM_SVCS_CM_DEFAULT, LLVM_SVCS_RM_STATIC,
                                          &instrBytes, &instrBytesLen, &err, &errLen);

  if (assembleResult || errLen)
  {
    errors = err;
    BNLlvmServicesAssembleFree(instrBytes, err);
    return false;
  }

  result.Clear();
  result.Append(instrBytes, instrBytesLen);
  BNLlvmServicesAssembleFree(instrBytes, err);
  return true;
}

/*
 * AAPCS (ARM EABI) Calling Convention - Modern default
 * - r0-r3: arguments
 * - r0: return value, r1: high word of 64-bit return
 * - r0-r3, r12, lr: caller-saved (volatile)
 * - r4-r11: callee-saved (non-volatile)
 * - 8-byte stack alignment at public interfaces
 */
class Armv5AAPCSCallingConvention : public CallingConvention
{
public:
  Armv5AAPCSCallingConvention(Architecture *arch) : CallingConvention(arch, "aapcs")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3};
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3, REG_R12, REG_LR};
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R9, REG_R10, REG_R11};
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;
  }

  virtual uint32_t GetHighIntegerReturnValueRegister() override
  {
    return REG_R1;
  }

  virtual uint32_t GetGlobalPointerRegister() override
  {
    return REG_R9;  // Common embedded usage for static base / TLS
  }
};

// Keep cdecl as alias for compatibility
class Armv5CallingConvention : public CallingConvention
{
public:
  Armv5CallingConvention(Architecture *arch) : CallingConvention(arch, "cdecl")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3};
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3, REG_R12, REG_LR};
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R9, REG_R10, REG_R11};
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;
  }

  virtual uint32_t GetHighIntegerReturnValueRegister() override
  {
    return REG_R1;
  }
};

/*
 * APCS-32 / ATPCS Calling Convention - Legacy embedded
 * Same as AAPCS but with 4-byte stack alignment
 */
class Armv5APCSCallingConvention : public CallingConvention
{
public:
  Armv5APCSCallingConvention(Architecture *arch) : CallingConvention(arch, "apcs")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3};
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3, REG_R12, REG_LR};
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R9, REG_R10, REG_R11};
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;
  }

  virtual uint32_t GetHighIntegerReturnValueRegister() override
  {
    return REG_R1;
  }

  virtual uint32_t GetGlobalPointerRegister() override
  {
    return REG_R9;  // APCS commonly uses r9 as SB (static base)
  }
};

/*
 * IRQ / Exception Handler Calling Convention
 * - No arguments (hardware-initiated)
 * - No return registers (uses exception return)
 * - All GPRs treated as caller-saved (conservative)
 * - 4-byte stack alignment
 */
class Armv5IRQCallingConvention : public CallingConvention
{
public:
  Armv5IRQCallingConvention(Architecture *arch) : CallingConvention(arch, "irq-handler")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{};  // No arguments
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    // Conservative: treat all GPRs as caller-saved
    return vector<uint32_t>{
      REG_R0, REG_R1, REG_R2, REG_R3, REG_R4, REG_R5, REG_R6, REG_R7,
      REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_LR
    };
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{};  // None - all clobbered
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;  // Not really used, but need to return something valid
  }

  virtual bool IsEligibleForHeuristics() override
  {
    return false;  // Don't auto-detect this convention
  }
};

/*
 * RTOS Task Entry Calling Convention
 * Many RTOS task entry points are invoked with:
 * - r0 = argc (or task parameter)
 * - r1 = argv (or additional parameter)
 * - lr = task exit stub
 * - sp = task stack top
 * Tasks generally do not return normally.
 */
class Armv5TaskEntryCallingConvention : public CallingConvention
{
public:
  Armv5TaskEntryCallingConvention(Architecture *arch) : CallingConvention(arch, "task-entry")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1};  // argc, argv or task params
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3, REG_R12, REG_LR};
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R9, REG_R10, REG_R11};
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;  // Tasks don't return, but need valid register
  }

  virtual uint32_t GetGlobalPointerRegister() override
  {
    return REG_R9;
  }

  virtual bool IsEligibleForHeuristics() override
  {
    return false;  // Don't auto-detect - must be explicitly applied
  }
};

/*
 * Linux System Call Calling Convention
 * R7 contains syscall number, R0-R6 contain arguments
 */
class LinuxArmv5SystemCallConvention : public CallingConvention
{
public:
  LinuxArmv5SystemCallConvention(Architecture *arch) : CallingConvention(arch, "linux-syscall")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{REG_R7, REG_R0, REG_R1, REG_R2, REG_R3, REG_R4, REG_R5, REG_R6};
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    return vector<uint32_t>{REG_R0};
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R10, REG_R11};
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;
  }

  virtual bool IsEligibleForHeuristics() override
  {
    return false;
  }
};

/*
 * Function Recognizer for ARM thunks and tail-call stubs
 *
 * Detects simple functions that are just wrappers/thunks:
 * - Single unconditional branch (B target) - tail call thunk
 * - LDR PC, [PC, #imm] - jump through literal pool (PLT-style)
 * - MOV r0, #const + BX LR - constant return function
 *
 * When a thunk targets an imported function, marks the thunk as an import.
 */
class ArmFunctionRecognizer : public FunctionRecognizer
{
public:
  virtual bool RecognizeLowLevelIL(BinaryView *data, Function *func, LowLevelILFunction *il) override
  {
    size_t instrCount = il->GetInstructionCount();
    if (instrCount == 0 || instrCount > 3)
      return false;

    /* Pattern 1: Single jump/tailcall to a constant address */
    if (instrCount == 1)
    {
      LowLevelILInstruction instr = il->GetInstruction(0);
      if (instr.operation == LLIL_JUMP || instr.operation == LLIL_TAILCALL)
      {
        LowLevelILInstruction dest = instr.GetDestExpr();
        if (dest.operation == LLIL_CONST_PTR || dest.operation == LLIL_CONST)
        {
          uint64_t target = dest.GetConstant();

          /* Check if target is an imported function */
          Ref<Symbol> sym = data->GetSymbolByAddress(target);
          if (sym && sym->GetType() == ImportedFunctionSymbol)
          {
            Ref<Function> targetFunc = data->GetRecentAnalysisFunctionForAddress(target);
            if (targetFunc)
            {
              Confidence<Ref<Type>> type = targetFunc->GetType();
              data->DefineImportedFunction(sym, func, type.GetValue());
              return true;
            }
          }
        }
      }
    }

    /* Pattern 2: SET_REG r0, const + RETURN (constant return function)
     * These are common for error code returns, boolean returns, etc.
     */
    if (instrCount == 2)
    {
      LowLevelILInstruction instr0 = il->GetInstruction(0);
      LowLevelILInstruction instr1 = il->GetInstruction(1);

      if (instr0.operation == LLIL_SET_REG && instr1.operation == LLIL_RET)
      {
        /* Could potentially set return type to int/bool based on value */
        /* For now, just recognize the pattern */
      }
    }

    return false;
  }
};

/*
 * Imported Function Recognizer for Thumb veneers
 * Detects inline veneers for thumb -> arm transitions
 */
class ThumbImportedFunctionRecognizer : public FunctionRecognizer
{
public:
  virtual bool RecognizeLowLevelIL(BinaryView *data, Function *func, LowLevelILFunction *il) override
  {
    /* Detection for inline veneers for thumb -> arm transitions */
    if (il->GetInstructionCount() == 1)
    {
      LowLevelILInstruction instr = il->GetInstruction(0);
      if ((instr.operation == LLIL_JUMP) || (instr.operation == LLIL_TAILCALL))
      {
        LowLevelILInstruction operand = instr.GetDestExpr();
        if (operand.operation == LLIL_CONST_PTR)
        {
          uint64_t entry = operand.GetConstant();
          if (entry == (func->GetStart() + 4))
          {
            Ref<Function> entryFunc = data->GetRecentAnalysisFunctionForAddress(entry);
            Ref<Symbol> sym = data->GetSymbolByAddress(entry);
            if (!entryFunc || !sym || (sym->GetType() != ImportedFunctionSymbol))
              return false;

            Confidence<Ref<Type>> type = entryFunc->GetType();
            data->DefineImportedFunction(sym, func, type.GetValue());
            return true;
          }
        }
      }
    }

    return false;
  }
};

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
                               uint8_t *dest, size_t len) override
  {
    (void)view;
    BNRelocationInfo info = reloc->GetInfo();
    if (len < info.size)
      return false;
    Ref<Symbol> sym = reloc->GetSymbol();
    uint32_t target = (uint32_t)reloc->GetTarget();
    uint32_t *dest32 = (uint32_t *)dest;

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
        LogError("Unsupported relocation R_ARM_CALL to thumb target");
        break;
      }
      struct _bl
      {
        int32_t imm : 24;
        uint32_t group1 : 4;
        uint32_t cond : 4;
      };
      _bl *bl = (_bl *)dest32;
      int64_t newTarget = (target + (info.implicitAddend ? ((bl->imm << 2) + 8) : info.addend)) - reloc->GetAddress();
      if ((newTarget - 8) > 0x3ffffff)
      {
        LogError("Unsupported relocation R_ARM_CALL @ 0x%" PRIx64 " with target greater than 0x3ffffff: 0x%" PRIx64, reloc->GetAddress(), newTarget - 8);
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

      _thumb32_bl_hw1 *bl_hw1 = (_thumb32_bl_hw1 *)dest;
      _thumb32_bl_hw2 *bl_hw2 = (_thumb32_bl_hw2 *)(dest + 2);
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
        LogError("Unsupported relocation R_ARM_JUMP24 to thumb target");
        break;
      }
      struct _b
      {
        int32_t imm : 24;
        uint32_t group1 : 4;
        uint32_t cond : 4;
      };
      _b *b = (_b *)dest32;
      int64_t newTarget = (target + (info.implicitAddend ? ((b->imm << 2) + 8) : info.addend)) - reloc->GetAddress();
      if ((newTarget - 8) > 0x3ffffff)
      {
        LogError("Unsupported relocation R_ARM_JUMP24 0x%" PRIx64 " with target greater than 0x3ffffff: 0x%" PRIx64, reloc->GetAddress(), newTarget - 8);
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
      _mov *mov = (_mov *)dest32;
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
      _mov *mov = (_mov *)dest32;
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
      _mov *mov = (_mov *)dest32;
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
                                 vector<BNRelocationInfo> &result) override
  {
    (void)view;
    (void)arch;
    set<uint64_t> relocTypes;
    for (auto &reloc : result)
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

      case R_ARM_THM_ABS5:
      case R_ARM_THM_PC8:
      case R_ARM_THM_SWI8:
      case R_ARM_THM_XPC22:
      case R_ARM_THM_MOVW_PREL_NC:
      case R_ARM_THM_MOVT_PREL:
      case R_ARM_THM_JUMP19:
      case R_ARM_THM_JUMP6:
      case R_ARM_THM_ALU_PREL_11_0:
      case R_ARM_THM_PC12:
      case R_ARM_THM_MOVW_BREL_NC:
      case R_ARM_THM_MOVT_BREL:
      case R_ARM_THM_MOVW_BREL:
      case R_ARM_THM_JUMP11:
      case R_ARM_THM_JUMP8:
      case R_ARM_THM_TLS_DESCSEQ16:
      case R_ARM_THM_TLS_DESCSEQ32:
      case R_ARM_THM_RPC22:

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
      case R_ARM_TLS_GD32:
      case R_ARM_TLS_LDM32:
      case R_ARM_TLS_LDO32:
      case R_ARM_TLS_LE32:
      case R_ARM_TLS_LDO12:
      case R_ARM_TLS_LE12:
      case R_ARM_TLS_IE12GP:
      case R_ARM_ME_TOO:
      case R_ARM_RXPC25:
      case R_ARM_RSBREL32:
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
    for (auto &reloc : relocTypes)
      LogWarn("Unsupported ELF relocation: %s", GetRelocationString((ElfArmRelocationType)reloc));
    return true;
  }
};

/*
 * Parse .ARM.attributes section to extract Tag_CPU_arch
 *
 * The .ARM.attributes section is a non-loadable ELF section (SHF_ALLOC not set),
 * so it's not mapped into the BinaryView's address space. We must parse the
 * ELF section headers directly from the parent (raw) view to find it.
 *
 * The .ARM.attributes section format (from ARM ABI):
 * - byte: format version ('A' = 0x41)
 * - subsections:
 *   - uint32_t: subsection length (including tag and length)
 *   - string: vendor name (null-terminated, "aeabi" for standard)
 *   - sub-subsections:
 *     - byte: tag (1 = Tag_File for file-scope attributes)
 *     - uint32_t: size
 *     - attributes: tag-value pairs (ULEB128 encoded)
 *
 * Tag_CPU_arch values (Tag 6):
 *   0 = Pre-v4
 *   1 = ARMv4
 *   2 = ARMv4T
 *   3 = ARMv5T
 *   4 = ARMv5TE
 *   5 = ARMv5TEJ
 *   6 = ARMv6
 *   7 = ARMv6KZ
 *   8 = ARMv6T2
 *   9 = ARMv6K
 *   10 = ARMv7
 *   11 = ARMv6-M
 *   12 = ARMv6S-M
 *   13 = ARMv7E-M
 *   14 = ARMv8-A (and later)
 *
 * Returns: -1 if not found/error, otherwise the Tag_CPU_arch value
 */
static int ParseArmAttributesCpuArch(BinaryView* view)
{
  if (!view)
    return -1;

  /* Get the parent (raw) view to access non-loaded sections */
  Ref<BinaryView> parent = view->GetParentView();
  if (!parent)
  {
    /* Try to get raw view through the file object */
    Ref<FileMetadata> file = view->GetFile();
    if (file)
      parent = file->GetViewOfType("Raw");
  }

  if (!parent)
    return -1;

  /* Read ELF header from raw view */
  uint8_t ehdr[52];  /* 32-bit ELF header size */
  if (parent->Read(ehdr, 0, 52) != 52)
    return -1;

  /* Verify ELF magic and 32-bit */
  if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F')
    return -1;
  if (ehdr[4] != 1)  /* EI_CLASS: must be 32-bit */
    return -1;

  bool littleEndian = (ehdr[5] == 1);  /* EI_DATA */

  /* Parse section header table info from ELF header */
  auto readU16 = [littleEndian](const uint8_t* p) -> uint16_t {
    return littleEndian ? (p[0] | (p[1] << 8)) : ((p[0] << 8) | p[1]);
  };
  auto readU32 = [littleEndian](const uint8_t* p) -> uint32_t {
    return littleEndian ?
      (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24)) :
      ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
  };

  uint32_t e_shoff = readU32(&ehdr[0x20]);      /* Section header table offset */
  uint16_t e_shentsize = readU16(&ehdr[0x2e]);  /* Section header entry size */
  uint16_t e_shnum = readU16(&ehdr[0x30]);      /* Number of section headers */
  uint16_t e_shstrndx = readU16(&ehdr[0x32]);   /* Section name string table index */

  if (e_shoff == 0 || e_shnum == 0 || e_shstrndx >= e_shnum)
    return -1;
  if (e_shentsize < 40)  /* Minimum section header size */
    return -1;

  /* Read section name string table header */
  uint8_t strtab_shdr[40];
  if (parent->Read(strtab_shdr, e_shoff + e_shstrndx * e_shentsize, 40) != 40)
    return -1;

  uint32_t strtab_offset = readU32(&strtab_shdr[0x10]);
  uint32_t strtab_size = readU32(&strtab_shdr[0x14]);

  if (strtab_size > 0x10000)  /* Sanity check */
    strtab_size = 0x10000;

  /* Read string table */
  DataBuffer strtab = parent->ReadBuffer(strtab_offset, strtab_size);
  if (strtab.GetLength() < strtab_size)
    return -1;

  /* Scan section headers for .ARM.attributes */
  for (uint16_t i = 0; i < e_shnum; i++)
  {
    uint8_t shdr[40];
    if (parent->Read(shdr, e_shoff + i * e_shentsize, 40) != 40)
      continue;

    uint32_t sh_name = readU32(&shdr[0x00]);
    uint32_t sh_offset = readU32(&shdr[0x10]);
    uint32_t sh_size = readU32(&shdr[0x14]);

    if (sh_name >= strtab.GetLength())
      continue;

    /* Get section name from string table */
    const char* name = (const char*)strtab.GetData() + sh_name;
    if (strcmp(name, ".ARM.attributes") != 0)
      continue;

    /* Found .ARM.attributes section - read and parse it */
    if (sh_size < 5 || sh_size > 4096)
      return -1;

    DataBuffer attrBuf = parent->ReadBuffer(sh_offset, sh_size);
    if (attrBuf.GetLength() < sh_size)
      return -1;

    const uint8_t* data = (const uint8_t*)attrBuf.GetData();
    size_t len = attrBuf.GetLength();
    size_t pos = 0;

    /* Check format version */
    if (data[pos++] != 'A')
      return -1;

    /* Parse subsections */
    while (pos + 4 < len)
    {
      /* Subsection length (always little-endian in attributes) */
      uint32_t subLen = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
      pos += 4;

      if (subLen < 5 || pos + subLen - 4 > len)
        break;

      size_t subEnd = pos + subLen - 4;

      /* Vendor name (null-terminated string) */
      size_t vendorStart = pos;
      while (pos < subEnd && data[pos] != 0)
        pos++;
      if (pos >= subEnd)
        break;
      pos++;  /* Skip null terminator */

      /* Check if this is the "aeabi" vendor (standard ARM attributes) */
      bool isAeabi = (strcmp((const char*)&data[vendorStart], "aeabi") == 0);

      if (!isAeabi)
      {
        pos = subEnd;
        continue;
      }

      /* Parse sub-subsections within aeabi */
      while (pos + 5 < subEnd)
      {
        uint8_t tag = data[pos++];

        /* Sub-subsection size (little-endian) */
        if (pos + 4 > subEnd)
          break;
        uint32_t ssSize = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
        pos += 4;

        if (ssSize < 5 || pos + ssSize - 5 > subEnd)
          break;

        size_t ssEnd = pos + ssSize - 5;

        /* Only process Tag_File (1) - file-scope attributes */
        if (tag != 1)
        {
          pos = ssEnd;
          continue;
        }

        /* Parse attribute tag-value pairs */
        while (pos < ssEnd)
        {
          /* Read ULEB128 tag */
          uint32_t attrTag = 0;
          uint32_t shift = 0;
          while (pos < ssEnd)
          {
            uint8_t b = data[pos++];
            attrTag |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0)
              break;
            shift += 7;
          }

          if (pos >= ssEnd)
            break;

          /* Determine if value is ULEB128 or NTBS based on tag */
          /* Tags 4, 5, 32, 65, 67 are strings; most others are ULEB128 */
          bool isString = (attrTag == 4 || attrTag == 5 || attrTag == 32 ||
                           attrTag == 65 || attrTag == 67);

          if (isString)
          {
            /* Skip null-terminated string */
            while (pos < ssEnd && data[pos] != 0)
              pos++;
            if (pos < ssEnd)
              pos++;  /* Skip null */
          }
          else
          {
            /* Read ULEB128 value */
            uint32_t attrVal = 0;
            shift = 0;
            while (pos < ssEnd)
            {
              uint8_t b = data[pos++];
              attrVal |= (b & 0x7F) << shift;
              if ((b & 0x80) == 0)
                break;
              shift += 7;
            }

            /* Tag 6 is Tag_CPU_arch */
            if (attrTag == 6)
              return (int)attrVal;
          }
        }

        pos = ssEnd;
      }

      pos = subEnd;
    }

    /* Found section but couldn't parse Tag_CPU_arch */
    return -1;
  }

  return -1;
}

/*
 * ELF ARM Platform Recognizer for ARMv5
 *
 * This callback is invoked by the ELF loader to determine which platform/architecture
 * to use for ARM binaries (EM_ARM = 0x28). It parses .ARM.attributes to detect ARMv5.
 *
 * Detection strategy:
 * 1. Parse .ARM.attributes section for Tag_CPU_arch (authoritative)
 * 2. Fall back to e_flags EABI version heuristics for older binaries
 *
 * Returns: ARMv5 platform if detected, nullptr to fall through to ARMv7
 */
static Ref<Platform> ElfArmv5PlatformRecognize(BinaryView* view, Metadata* metadata)
{
  if (!view)
    return nullptr;

  /* First, try to parse .ARM.attributes for authoritative CPU arch */
  int cpuArch = ParseArmAttributesCpuArch(view);
  if (cpuArch >= 0)
  {
    /*
     * Tag_CPU_arch values for ARMv5 family:
     *   3 = ARMv5T
     *   4 = ARMv5TE
     *   5 = ARMv5TEJ
     *
     * Also claim older architectures (pre-v4, v4, v4T) since ARMv5 is a superset.
     * ARMv6+ (values 6-14) should fall through to ARMv7.
     */
    if (cpuArch <= 5)
    {
      const char* archNames[] = {"Pre-v4", "ARMv4", "ARMv4T", "ARMv5T", "ARMv5TE", "ARMv5TEJ"};
      LogInfo("ELF .ARM.attributes Tag_CPU_arch=%d (%s): using armv5 architecture",
              cpuArch, archNames[cpuArch]);
      return Platform::GetByName("armv5");
    }

    /* ARMv6+ detected, let ARMv7 handle it */
    return nullptr;
  }

  /* Fall back to e_flags heuristics for binaries without .ARM.attributes */
  if (!metadata)
    return nullptr;

  /* Check ELF OS/ABI - we only handle Linux/SYSV (0) and GNU (3) */
  Ref<Metadata> abiMetadata = metadata->Get("EI_OSABI");
  if (abiMetadata && abiMetadata->IsUnsignedInteger())
  {
    uint64_t abi = abiMetadata->GetUnsignedInteger();
    if (abi != 0 && abi != 3)
      return nullptr;
  }

  /* Check e_flags for ARM EABI version hints */
  Ref<Metadata> flagsMetadata = metadata->Get("e_flags");
  if (!flagsMetadata || !flagsMetadata->IsUnsignedInteger())
    return nullptr;

  uint64_t flags = flagsMetadata->GetUnsignedInteger();

  /*
   * ARM EABI e_flags:
   * - EF_ARM_EABIMASK (0xFF000000): EABI version
   * - EF_ARM_EABI_VER1 (0x01000000): EABI v1 - typically ARMv4T/ARMv5
   * - EF_ARM_EABI_VER2 (0x02000000): EABI v2 - typically ARMv5
   *
   * Note: EABI version alone doesn't indicate CPU arch; modern toolchains
   * use EABI v5 for all ARM variants. The .ARM.attributes section is
   * authoritative, but older binaries may not have it.
   */
  #define EF_ARM_EABIMASK 0xFF000000
  #define EF_ARM_EABI_VER1 0x01000000
  #define EF_ARM_EABI_VER2 0x02000000

  uint64_t eabiVersion = flags & EF_ARM_EABIMASK;

  /* Claim binaries with older EABI versions as ARMv5 */
  if (eabiVersion == EF_ARM_EABI_VER1 || eabiVersion == EF_ARM_EABI_VER2)
  {
    LogInfo("ELF e_flags 0x%08" PRIx64 " indicates early ARM EABI: using armv5 architecture", flags);
    return Platform::GetByName("armv5");
  }

  return nullptr;
}

/*
 * Raw Binary Platform Recognizer for ARMv5
 *
 * This callback is invoked by the Mapped view type for raw binaries to determine
 * which platform/architecture to use. It inspects the raw bytes to detect ARM patterns.
 *
 * Detection strategy:
 * 1. Check for ARM vector table pattern at offset 0 (reset vector typically LDR PC or B instruction)
 * 2. Look for common ARM instruction patterns
 * 3. Use heuristics based on instruction density
 *
 * The BinaryView passed is the Raw view, allowing us to read bytes directly.
 *
 * Returns: ARMv5 platform if detected, nullptr to fall through to other architectures
 */
static Ref<Platform> RawArmv5PlatformRecognize(BinaryView* view, Metadata* metadata)
{
  if (!view)
    return nullptr;

  /* Read first 32 bytes to check for ARM vector table patterns */
  uint8_t buffer[32];
  size_t bytesRead = view->Read(buffer, 0, sizeof(buffer));
  if (bytesRead < 32)
    return nullptr;

  /*
   * Check for ARM vector table pattern (little-endian):
   * ARM processors typically start with a vector table at address 0 containing
   * LDR PC, [PC, #offset] (0xE59FF0xx) or B instructions (0xEAxxxxxx).
   */
  int armPatternCount = 0;

  for (int i = 0; i < 8; i++)
  {
    uint32_t word = buffer[i*4] | (buffer[i*4+1] << 8) | (buffer[i*4+2] << 16) | (buffer[i*4+3] << 24);

    /* Check for LDR PC, [PC, #imm] or branch instructions */
    if ((word & 0xFFFFF000) == 0xE59FF000 || /* LDR PC, [PC, #imm] */
        (word & 0xFF000000) == 0xEA000000 || /* B <offset> */
        (word & 0x0F000000) == 0x0A000000)   /* Bcc <offset> */
    {
      armPatternCount++;
    }
  }

  /* If we see at least 4 vector table entries that look like ARM code, claim it */
  if (armPatternCount >= 4)
  {
    LogInfo("Raw binary detected as ARM: vector table pattern found (%d/8 entries), claiming as armv5", armPatternCount);
    return Platform::GetByName("armv5");
  }

  return nullptr;
}

static void RegisterArmv5Architecture(const char *armName, const char *thumbName, BNEndianness endian)
{
  ArmCommonArchitecture *armv5 = new Armv5Architecture(armName, endian);
  ArmCommonArchitecture *thumb = InitThumbArchitecture(thumbName, endian);
  armv5->SetArmAndThumbArchitectures(armv5, thumb);
  thumb->SetArmAndThumbArchitectures(armv5, thumb);

  Architecture::Register(armv5);
  Architecture::Register(thumb);

  /* Register calling conventions for ARM */
  Ref<CallingConvention> conv;

  // AAPCS (modern default)
  Ref<CallingConvention> aapcsConv = new Armv5AAPCSCallingConvention(armv5);
  armv5->RegisterCallingConvention(aapcsConv);
  armv5->SetDefaultCallingConvention(aapcsConv);

  // cdecl (compatibility alias for AAPCS)
  conv = new Armv5CallingConvention(armv5);
  armv5->RegisterCallingConvention(conv);
  armv5->SetCdeclCallingConvention(conv);
  armv5->SetFastcallCallingConvention(conv);
  armv5->SetStdcallCallingConvention(conv);

  // APCS (legacy embedded)
  conv = new Armv5APCSCallingConvention(armv5);
  armv5->RegisterCallingConvention(conv);

  // IRQ/Exception handler convention
  conv = new Armv5IRQCallingConvention(armv5);
  armv5->RegisterCallingConvention(conv);

  // RTOS task entry convention
  conv = new Armv5TaskEntryCallingConvention(armv5);
  armv5->RegisterCallingConvention(conv);

  /* Register Linux system call convention for ARM */
  conv = new LinuxArmv5SystemCallConvention(armv5);
  armv5->RegisterCallingConvention(conv);

  /* Register function recognizer for ARM thunks */
  armv5->RegisterFunctionRecognizer(new ArmFunctionRecognizer());

  /* Register calling conventions for Thumb */
  // AAPCS (modern default)
  Ref<CallingConvention> thumbAapcsConv = new Armv5AAPCSCallingConvention(thumb);
  thumb->RegisterCallingConvention(thumbAapcsConv);
  thumb->SetDefaultCallingConvention(thumbAapcsConv);

  // cdecl (compatibility alias)
  conv = new Armv5CallingConvention(thumb);
  thumb->RegisterCallingConvention(conv);
  thumb->SetCdeclCallingConvention(conv);
  thumb->SetFastcallCallingConvention(conv);
  thumb->SetStdcallCallingConvention(conv);

  // APCS (legacy)
  conv = new Armv5APCSCallingConvention(thumb);
  thumb->RegisterCallingConvention(conv);

  // IRQ/Exception handler
  conv = new Armv5IRQCallingConvention(thumb);
  thumb->RegisterCallingConvention(conv);

  // RTOS task entry
  conv = new Armv5TaskEntryCallingConvention(thumb);
  thumb->RegisterCallingConvention(conv);

  /* Register Linux system call convention for Thumb */
  conv = new LinuxArmv5SystemCallConvention(thumb);
  thumb->RegisterCallingConvention(conv);

  /* Register function recognizer for Thumb veneers */
  thumb->RegisterFunctionRecognizer(new ThumbImportedFunctionRecognizer());

  /* Register platform recognizer for ELF ARM binaries
   *
   * We use RegisterPlatformRecognizer instead of RegisterArchitecture to avoid
   * conflicting with the ARMv7 plugin's registration for EM_ARM (0x28).
   *
   * The recognizer callback inspects ELF metadata to detect ARMv5-specific binaries:
   * - Checks e_flags for ARM EABI version and architecture hints
   * - Returns ARMv5 platform for pre-ARMv6 binaries
   * - Returns nullptr to fall through to ARMv7 for newer binaries
   *
   * Since recognizers are called LIFO (most recently added first), and this plugin
   * loads after ARMv7, our recognizer gets first chance to claim ARM ELF binaries.
   */
  Ref<BinaryViewType> elf = BinaryViewType::GetByName("ELF");
  if (elf)
  {
    elf->RegisterPlatformRecognizer(0x28, endian, ElfArmv5PlatformRecognize);
  }

  /* Register platform recognizer for raw binaries
   *
   * Try registering with both "Raw" and "Mapped" view types since either might
   * be used for bare metal/firmware binaries. We register a recognizer that
   * inspects raw bytes for ARM vector table patterns.
   * ID 0 is used since raw binaries don't have a machine type.
   */
  Ref<BinaryViewType> raw = BinaryViewType::GetByName("Raw");
  if (raw)
  {
    raw->RegisterPlatformRecognizer(0, endian, RawArmv5PlatformRecognize);
  }

  Ref<BinaryViewType> mapped = BinaryViewType::GetByName("Mapped");
  if (mapped)
  {
    mapped->RegisterPlatformRecognizer(0, endian, RawArmv5PlatformRecognize);
  }

  /* Register ELF relocation handler for both architectures */
  armv5->RegisterRelocationHandler("ELF", new Armv5ElfRelocationHandler());
  /*
      Missing:
      armv5->RegisterRelocationHandler("Mach-O", new ArmMachORelocationHandler());
      armv5->RegisterRelocationHandler("PE", new ArmPERelocationHandler());
      armv5->RegisterRelocationHandler("COFF", new ArmCOFFRelocationHandler());
  */

  thumb->RegisterRelocationHandler("ELF", new Armv5ElfRelocationHandler());
  /*
      Missing:
      thumb->RegisterRelocationHandler("Mach-O", new ArmMachORelocationHandler());
      thumb->RegisterRelocationHandler("COFF", new ArmCOFFRelocationHandler());
  */

  /* Set up standalone platform interworking - CRITICAL for proper ARM/Thumb switching */
  armv5->GetStandalonePlatform()->AddRelatedPlatform(thumb, thumb->GetStandalonePlatform());
  thumb->GetStandalonePlatform()->AddRelatedPlatform(armv5, armv5->GetStandalonePlatform());
}

extern "C"
{
  BN_DECLARE_CORE_ABI_VERSION

  BINARYNINJAPLUGIN void CorePluginDependencies()
  {
    AddOptionalPluginDependency("view_elf");
  }

  BINARYNINJAPLUGIN bool CorePluginInit()
  {
    RegisterArmv5Architecture("armv5", "armv5t", LittleEndian);
    InitArmv5FirmwareViewType();
    return true;
  }
}
