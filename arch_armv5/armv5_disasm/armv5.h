/*
 * ARMv5 Disassembler Header
 *
 * This header defines the data structures and functions for disassembling
 * ARMv5 (including ARMv5TE/ARMv5TEJ) instructions.
 *
 * Based on the ARM Architecture Reference Manual for ARMv5.
 * Follows the same patterns as the ARMv7 plugin in binaryninja-api/arch/armv7/.
 *
 * Features supported:
 * - Base ARMv5T instruction set
 * - DSP extensions (ARMv5TE) - enhanced multiply and saturating arithmetic
 * - CLZ (Count Leading Zeros)
 * - Improved ARM/Thumb interworking
 * - VFPv2 (optional floating-point)
 *
 * Features NOT supported (ARMv6/ARMv7 specific):
 * - Thumb-2 (only original 16-bit Thumb)
 * - NEON/Advanced SIMD
 * - VFPv3 extensions
 * - Memory barriers (DMB, DSB, ISB)
 * - IT blocks
 */

#ifndef ARMV5_DISASM_H
#define ARMV5_DISASM_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_MSC_VER)
	#define snprintf _snprintf
	#define restrict __restrict
	#define inline __inline
#else
	#include <stdlib.h>
	#ifdef __cplusplus
	#define restrict __restrict
	#endif
#endif

#define MAX_OPERANDS 6

#define UNCONDITIONAL(c) (((c) == COND_AL) || ((c) == COND_NV))
#define CONDITIONAL(c) (((c) != COND_AL) && ((c) != COND_NV))

#ifdef __cplusplus
#define restrict __restrict

namespace armv5 {
#endif

/* ARMv5 Operations - includes base ARM + DSP extensions */
enum Operation {
    ARMV5_UNDEFINED = 0,
    ARMV5_UNPREDICTABLE,

    /* Data Processing */
    ARMV5_AND,
    ARMV5_ANDS,
    ARMV5_EOR,
    ARMV5_EORS,
    ARMV5_SUB,
    ARMV5_SUBS,
    ARMV5_RSB,
    ARMV5_RSBS,
    ARMV5_ADD,
    ARMV5_ADDS,
    ARMV5_ADC,
    ARMV5_ADCS,
    ARMV5_SBC,
    ARMV5_SBCS,
    ARMV5_RSC,
    ARMV5_TST,
    ARMV5_TEQ,
    ARMV5_CMP,
    ARMV5_CMN,
    ARMV5_ORR,
    ARMV5_ORRS,
    ARMV5_MOV,
    ARMV5_MOVS,
    ARMV5_BIC,
    ARMV5_BICS,
    ARMV5_MVN,
    ARMV5_MVNS,

    /* Shift operations (Thumb uses these as separate mnemonics) */
    ARMV5_LSL,
    ARMV5_LSLS,
    ARMV5_LSR,
    ARMV5_LSRS,
    ARMV5_ASR,
    ARMV5_ASRS,
    ARMV5_ROR,
    ARMV5_RORS,

    /* ADR (Address to Register - Thumb pseudo-op) */
    ARMV5_ADR,

    /* Multiply */
    ARMV5_MUL,
    ARMV5_MULS,
    ARMV5_MLA,
    ARMV5_UMULL,
    ARMV5_UMLAL,
    ARMV5_SMULL,
    ARMV5_SMLAL,

    /* DSP Multiply Extensions (ARMv5TE) */
    ARMV5_SMULBB,
    ARMV5_SMULBT,
    ARMV5_SMULTB,
    ARMV5_SMULTT,
    ARMV5_SMULWB,
    ARMV5_SMULWT,
    ARMV5_SMLABB,
    ARMV5_SMLABT,
    ARMV5_SMLATB,
    ARMV5_SMLATT,
    ARMV5_SMLAWB,
    ARMV5_SMLAWT,
    ARMV5_SMLALBB,
    ARMV5_SMLALBT,
    ARMV5_SMLALTB,
    ARMV5_SMLALTT,

    /* Saturating Arithmetic (ARMv5TE) */
    ARMV5_QADD,
    ARMV5_QSUB,
    ARMV5_QDADD,
    ARMV5_QDSUB,

    /* Count Leading Zeros (ARMv5T) */
    ARMV5_CLZ,

    /* Branch */
    ARMV5_B,
    ARMV5_BL,
    ARMV5_BX,
    ARMV5_BLX,

    /* Load/Store */
    ARMV5_LDR,
    ARMV5_LDRB,
    ARMV5_LDRH,
    ARMV5_LDRSB,
    ARMV5_LDRSH,
    ARMV5_LDRD,
    ARMV5_STR,
    ARMV5_STRB,
    ARMV5_STRH,
    ARMV5_STRD,

    /* Load/Store Multiple */
    ARMV5_LDM,
    ARMV5_LDMIA,
    ARMV5_LDMIB,
    ARMV5_LDMDA,
    ARMV5_LDMDB,
    ARMV5_STM,
    ARMV5_STMIA,
    ARMV5_STMIB,
    ARMV5_STMDA,
    ARMV5_STMDB,
    ARMV5_PUSH,
    ARMV5_POP,

    /* Swap */
    ARMV5_SWP,
    ARMV5_SWPB,

    /* Software Interrupt */
    ARMV5_SWI,
    ARMV5_SVC,
    ARMV5_BKPT,

    /* Coprocessor */
    ARMV5_CDP,
    ARMV5_LDC,
    ARMV5_STC,
    ARMV5_MCR,
    ARMV5_MRC,
    ARMV5_MCRR,
    ARMV5_MRRC,

    /* Status Register */
    ARMV5_MRS,
    ARMV5_MSR,

    /* Preload (ARMv5TE) */
    ARMV5_PLD,

    /* VFPv2 Instructions (Optional) */
    ARMV5_VMOV,
    ARMV5_VADD,
    ARMV5_VSUB,
    ARMV5_VMUL,
    ARMV5_VNMUL,
    ARMV5_VMLA,
    ARMV5_VMLS,
    ARMV5_VDIV,
    ARMV5_VNEG,
    ARMV5_VABS,
    ARMV5_VSQRT,
    ARMV5_VCMP,
    ARMV5_VCMPE,
    ARMV5_VCVT,
    ARMV5_VLDR,
    ARMV5_VSTR,
    ARMV5_VLDM,
    ARMV5_VSTM,
    ARMV5_VPUSH,
    ARMV5_VPOP,
    ARMV5_VMRS,
    ARMV5_VMSR,
    ARMV5_FMSTAT,

    /* Pseudo-ops */
    ARMV5_NOP,
    ARMV5_UDF,

    ARMV5_END_OPERATION
};

/* Shift types */
enum Shift {
    SHIFT_NONE = 0,
    SHIFT_LSL,
    SHIFT_LSR,
    SHIFT_ASR,
    SHIFT_ROR,
    SHIFT_RRX
};

/* Condition codes */
enum Condition
{
    COND_EQ,     // 0000: Equal (Z set)
    COND_NE,     // 0001: Not equal (Z clear)
    COND_CS,     // 0010: Carry set/unsigned higher or same (C set)
    COND_CC,     // 0011: Carry clear/unsigned lower (C clear)
    COND_MI,     // 0100: Minus/negative (N set)
    COND_PL,     // 0101: Plus/positive or zero (N clear)
    COND_VS,     // 0110: Overflow (V set)
    COND_VC,     // 0111: No overflow (V clear)
    COND_HI,     // 1000: Unsigned higher (C set and Z clear)
    COND_LS,     // 1001: Unsigned lower or same (C clear or Z set)
    COND_GE,     // 1010: Signed greater than or equal (N == V)
    COND_LT,     // 1011: Signed less than (N != V)
    COND_GT,     // 1100: Signed greater than (Z clear and N == V)
    COND_LE,     // 1101: Signed less than or equal (Z set or N != V)
    COND_AL,     // 1110: Always (unconditional)
    COND_NV      // 1111: Never (ARMv5: unpredictable, ARMv6+: unconditional for certain instructions)
};

/* Registers - matches ARMv7 numbering pattern */
enum Register {
    REG_R0 = 0,
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
    REG_SP, REG_R13 = 13,
    REG_LR, REG_R14 = 14,
    REG_PC, REG_R15 = 15,

    /* VFPv2 single-precision registers (s0-s31) - sequential after core regs */
    REG_S0,
    REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
    REG_S8, REG_S9, REG_S10, REG_S11, REG_S12, REG_S13, REG_S14, REG_S15,
    REG_S16, REG_S17, REG_S18, REG_S19, REG_S20, REG_S21, REG_S22, REG_S23,
    REG_S24, REG_S25, REG_S26, REG_S27, REG_S28, REG_S29, REG_S30, REG_S31,

    /* VFPv2 double-precision registers (d0-d15) */
    REG_D0,
    REG_D1, REG_D2, REG_D3, REG_D4, REG_D5, REG_D6, REG_D7,
    REG_D8, REG_D9, REG_D10, REG_D11, REG_D12, REG_D13, REG_D14, REG_D15,

    /* Special registers - after VFP regs */
    REGS_CPSR,
    REGS_CPSR_C,
    REGS_CPSR_X,
    REGS_CPSR_XC,
    REGS_CPSR_S,
    REGS_CPSR_SC,
    REGS_CPSR_SX,
    REGS_CPSR_SXC,
    REGS_CPSR_F,
    REGS_CPSR_FC,
    REGS_CPSR_FX,
    REGS_CPSR_FXC,
    REGS_CPSR_FS,
    REGS_CPSR_FSC,
    REGS_CPSR_FSX,
    REGS_CPSR_FSXC,
    REGS_SPSR,
    REGS_SPSR_C,
    REGS_SPSR_X,
    REGS_SPSR_XC,
    REGS_SPSR_S,
    REGS_SPSR_SC,
    REGS_SPSR_SX,
    REGS_SPSR_SXC,
    REGS_SPSR_F,
    REGS_SPSR_FC,
    REGS_SPSR_FX,
    REGS_SPSR_FXC,
    REGS_SPSR_FS,
    REGS_SPSR_FSC,
    REGS_SPSR_FSX,
    REGS_SPSR_FSXC,

    /* VFP system registers */
    REGS_FPSID,
    REGS_FPSCR,
    REGS_FPEXC,

    REG_INVALID,

    /* Legacy aliases for backward compatibility */
    REG_CPSR = REGS_CPSR,
    REG_SPSR = REGS_SPSR,
    REG_FPSID = REGS_FPSID,
    REG_FPSCR = REGS_FPSCR,
    REG_FPEXC = REGS_FPEXC,
    REG_NONE = REG_INVALID
};

/* Operand class */
enum OperandClass {
    NONE = 0,
    IMM,            /* Immediate value */
    LABEL,          /* Branch target label */
    REG,            /* Register */
    REG_LIST,       /* Register list for LDM/STM */
    REG_COPROCP,    /* Coprocessor number (p0-p15) */
    REG_COPROCC,    /* Coprocessor register (c0-c15) */
    COPROC_OPC,     /* Coprocessor opcode (plain number, no #) */
    MEM_IMM,        /* Memory with immediate offset */
    MEM_REG,        /* Memory with register offset */
    MEM_PRE_IDX,    /* Pre-indexed memory access */
    MEM_POST_IDX,   /* Post-indexed memory access */
    FIMM,           /* Floating-point immediate */
    COPROC,         /* Coprocessor operand (deprecated, use REG_COPROCP) */
    SYS_REG,        /* System register (CPSR, SPSR) */
    SHIFT_IMM,      /* Shift by immediate */
    SHIFT_REG       /* Shift by register */
};

/* Data type for VFP/SIMD operations - matches ARMv7 pattern */
enum DataType {
    DT_NONE = 0,
    DT_S8,
    DT_S16,
    DT_S32,
    DT_S64,
    DT_U8,
    DT_U16,
    DT_U32,
    DT_U64,
    DT_I8,
    DT_I16,
    DT_I32,
    DT_I64,
    DT_F16,
    DT_F32,
    DT_F64,
    DT_8,
    DT_16,
    DT_32,
    DT_64,
    DT_END
};

/* Instruction operand - matches ARMv7 pattern */
struct InstructionOperand {
    enum OperandClass cls;
    struct {
        uint32_t wb:1;          /* Write back */
        uint32_t add:1;         /* Add offset (1) or subtract (0) */
        uint32_t hasElements:1; /* Does the register have an array index */
        uint32_t emptyElement:1;
        uint32_t offsetRegUsed:1; /* Is the offset register being used */
    } flags;
    enum Register reg;
    enum Register offset;    /* Offset register */
    enum Shift shift;
    union {
        uint32_t imm;
        int64_t imm64;
        double immd;
        float immf;
    };
};

/* Decoded instruction - matches ARMv7 pattern */
struct Instruction {
    enum Operation operation;
    enum Condition cond;
    enum DataType dataType;
    uint32_t setsFlags;
    uint32_t unpredictable;
    struct InstructionOperand operands[MAX_OPERANDS];
};

/* C typedefs - only needed for C compilation */
#ifndef __cplusplus
	typedef enum OperandClass OperandClass;
	typedef enum Operation Operation;
	typedef enum Shift Shift;
	typedef enum Condition Condition;
	typedef enum Register Register;
	typedef enum DataType DataType;
	typedef struct InstructionOperand InstructionOperand;
	typedef struct Instruction Instruction;
#endif

/* Main disassembly functions - matches ARMv7 pattern */
#ifdef __cplusplus
	extern "C" {
#endif
	/**
	 * Decompose a 32-bit ARM instruction
	 *
	 * @param instructionValue  The 32-bit instruction opcode
	 * @param instruction       Output instruction structure (must be zeroed by caller)
	 * @param address           Address of the instruction
	 * @param bigEndian         Non-zero if big-endian
	 * @return                  0 on success, non-zero on failure
	 */
	uint32_t armv5_decompose(
	    uint32_t instructionValue,
	    struct Instruction* restrict instruction,
	    uint32_t address,
	    uint32_t bigEndian);

	/**
	 * Decompose a 16-bit Thumb instruction
	 *
	 * @param instructionValue  The 16-bit instruction opcode
	 * @param instruction       Output instruction structure (must be zeroed by caller)
	 * @param address           Address of the instruction
	 * @param bigEndian         Non-zero if big-endian
	 * @return                  0 on success, non-zero on failure
	 */
	uint32_t thumb_decompose(
	    uint16_t instructionValue,
	    struct Instruction* restrict instruction,
	    uint32_t address,
	    uint32_t bigEndian);

	/**
	 * Disassemble an instruction to text
	 *
	 * @param instruction   The decoded instruction
	 * @param outBuffer     Output buffer for disassembly text
	 * @param outBufferSize Size of output buffer
	 * @return              0 on success, non-zero on failure
	 */
	uint32_t armv5_disassemble(
	    struct Instruction* restrict instruction,
	    char* outBuffer,
	    uint32_t outBufferSize);

	/* Helper functions */
	const char* get_operation(enum Operation operation);
	const char* get_condition(enum Condition cond);
	const char* get_register_name(enum Register reg);
	const char* get_shift(enum Shift shift);
	uint32_t get_register_size(enum Register reg);

#ifdef __cplusplus
	} //end extern "C"
#endif

#ifdef __cplusplus
} //end namespace
#endif

#endif /* ARMV5_DISASM_H */
