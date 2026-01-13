#pragma once

#include "binaryninjaapi.h"
#include "armv5_disasm/armv5.h"

#define IL_FLAG_N 0
#define IL_FLAG_Z 2
#define IL_FLAG_C 4
#define IL_FLAG_V 6
#define IL_FLAG_Q 8

#define IL_FLAGWRITE_NONE 0
#define IL_FLAGWRITE_ALL 1
#define IL_FLAGWRITE_NZ 2
#define IL_FLAGWRITE_CNZ 3
#define IL_FLAGWRITE_NZC 4
#define IL_FLAGWRITE_NZCV 5

struct decomp_result;

enum Armv5Intrinsic : uint32_t
{
	ARMV5_INTRIN_MRS,
	ARMV5_INTRIN_MSR,
	ARMV5_INTRIN_COPROC_GETONEWORD, // MRC
	ARMV5_INTRIN_COPROC_SENDONEWORD, // MCR
	ARMV5_INTRIN_COPROC_GETTWOWORDS, // MRRC
	ARMV5_INTRIN_COPROC_SENDTWOWORDS, // MCRR
	ARMV5_INTRIN_CLZ,
	ARMV5_INTRIN_QADD,
	ARMV5_INTRIN_QSUB,
	ARMV5_INTRIN_QDADD,
	ARMV5_INTRIN_QDSUB,
	ARMV5_INTRIN_BKPT,
	ARMV5_INTRIN_SWP,
	ARMV5_INTRIN_SWPB,
	ARMV5_INTRIN_PLD,
	ARMV5_INTRIN_DBG, // ARMv7+ but keep for compatibility
	// DSP multiply intrinsics
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
	// Coprocessor intrinsics (legacy - keep for compatibility)
	ARMV5_INTRIN_CDP,
	ARMV5_INTRIN_LDC,
	ARMV5_INTRIN_STC,
	ARMV5_INTRIN_MCR,
	ARMV5_INTRIN_MRC,
	ARMV5_INTRIN_COUNT  // Keep last for iteration
};

// Fake register for syscall info
enum {
	FAKEREG_SYSCALL_INFO = armv5::REG_INVALID + 1
};

bool GetLowLevelILForArmInstruction(BinaryNinja::Architecture* arch, uint64_t addr,
    BinaryNinja::LowLevelILFunction& il, armv5::Instruction& instr, size_t addrSize);
bool GetLowLevelILForThumbInstruction(BinaryNinja::Architecture* arch,
    BinaryNinja::LowLevelILFunction& il, decomp_result* instr);
BinaryNinja::ExprId GetCondition(BinaryNinja::LowLevelILFunction& il, uint32_t cond);
