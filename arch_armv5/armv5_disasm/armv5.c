/*
 * ARMv5 Disassembler Implementation
 *
 * Decodes ARMv5T/ARMv5TE/ARMv5TEJ 32-bit ARM instructions.
 * Follows the same patterns as the ARMv7 plugin in binaryninja-api/arch/armv7/.
 */

#define _CRT_SECURE_NO_WARNINGS
#include "armv5.h"
#include <stdio.h>

#ifdef __cplusplus
using namespace armv5;
#endif

/* Forward declarations for decoder functions - matching ARMv7 pattern */
uint32_t armv5_64_bit_transfers(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_branch_and_block_data_transfer(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_coprocessor_instruction_and_supervisor_call(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_data_processing_and_misc(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_data_processing_imm(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_data_processing_reg_shifted_reg(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_data_processing_reg(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_decompose(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address, uint32_t bigEndian);
uint32_t armv5_extension_register_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_extra_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_floating_point_data_processing(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_halfword_multiply_and_accumulate(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_load_store_word_and_unsigned_byte(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_miscellaneous(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_msr_imm_and_hints(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_multiply_and_accumulate(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_saturating_add_sub(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_synchronization_primitives(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_transfers(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv5_unconditional(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
typedef uint32_t (*armv5_decompose_instruction)(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);

/* Byte swap for big-endian support */
static inline uint32_t bswap32(uint32_t x) {
    return ((x & 0xff000000) >> 24) |
           ((x & 0x00ff0000) >> 8) |
           ((x & 0x0000ff00) << 8) |
           ((x & 0x000000ff) << 24);
}

static const char* operationString[] = {
    "undefined",      // ARMV5_UNDEFINED
    "unpredictable",  // ARMV5_UNPREDICTABLE
    /* Data Processing */
    "and",            // ARMV5_AND
    "ands",           // ARMV5_ANDS
    "eor",            // ARMV5_EOR
    "eors",           // ARMV5_EORS
    "sub",            // ARMV5_SUB
    "subs",           // ARMV5_SUBS
    "rsb",            // ARMV5_RSB
    "rsbs",           // ARMV5_RSBS
    "add",            // ARMV5_ADD
    "adds",           // ARMV5_ADDS
    "adc",            // ARMV5_ADC
    "adcs",           // ARMV5_ADCS
    "sbc",            // ARMV5_SBC
    "sbcs",           // ARMV5_SBCS
    "rsc",            // ARMV5_RSC
    "tst",            // ARMV5_TST
    "teq",            // ARMV5_TEQ
    "cmp",            // ARMV5_CMP
    "cmn",            // ARMV5_CMN
    "orr",            // ARMV5_ORR
    "orrs",           // ARMV5_ORRS
    "mov",            // ARMV5_MOV
    "movs",           // ARMV5_MOVS
    "bic",            // ARMV5_BIC
    "bics",           // ARMV5_BICS
    "mvn",            // ARMV5_MVN
    "mvns",           // ARMV5_MVNS
    /* Shift operations */
    "lsl",            // ARMV5_LSL
    "lsls",           // ARMV5_LSLS
    "lsr",            // ARMV5_LSR
    "lsrs",           // ARMV5_LSRS
    "asr",            // ARMV5_ASR
    "asrs",           // ARMV5_ASRS
    "ror",            // ARMV5_ROR
    "rors",           // ARMV5_RORS
    /* ADR */
    "adr",            // ARMV5_ADR
    /* Multiply */
    "mul",            // ARMV5_MUL
    "muls",           // ARMV5_MULS
    "mla",            // ARMV5_MLA
    "umull",          // ARMV5_UMULL
    "umlal",          // ARMV5_UMLAL
    "smull",          // ARMV5_SMULL
    "smlal",          // ARMV5_SMLAL
    /* DSP Multiply Extensions (ARMv5TE) */
    "smulbb",         // ARMV5_SMULBB
    "smulbt",         // ARMV5_SMULBT
    "smultb",         // ARMV5_SMULTB
    "smultt",         // ARMV5_SMULTT
    "smulwb",         // ARMV5_SMULWB
    "smulwt",         // ARMV5_SMULWT
    "smlabb",         // ARMV5_SMLABB
    "smlabt",         // ARMV5_SMLABT
    "smlatb",         // ARMV5_SMLATB
    "smlatt",         // ARMV5_SMLATT
    "smlawb",         // ARMV5_SMLAWB
    "smlawt",         // ARMV5_SMLAWT
    "smlalbb",        // ARMV5_SMLALBB
    "smlalbt",        // ARMV5_SMLALBT
    "smlaltb",        // ARMV5_SMLALTB
    "smlaltt",        // ARMV5_SMLALTT
    /* Saturating Arithmetic (ARMv5TE) */
    "qadd",           // ARMV5_QADD
    "qsub",           // ARMV5_QSUB
    "qdadd",          // ARMV5_QDADD
    "qdsub",          // ARMV5_QDSUB
    /* Count Leading Zeros (ARMv5T) */
    "clz",            // ARMV5_CLZ
    /* Branch */
    "b",              // ARMV5_B
    "bl",             // ARMV5_BL
    "bx",             // ARMV5_BX
    "blx",            // ARMV5_BLX
    /* Load/Store */
    "ldr",            // ARMV5_LDR
    "ldrb",           // ARMV5_LDRB
    "ldrh",           // ARMV5_LDRH
    "ldrsb",          // ARMV5_LDRSB
    "ldrsh",          // ARMV5_LDRSH
    "ldrd",           // ARMV5_LDRD
    "str",            // ARMV5_STR
    "strb",           // ARMV5_STRB
    "strh",           // ARMV5_STRH
    "strd",           // ARMV5_STRD
    /* Load/Store Multiple */
    "ldm",            // ARMV5_LDM
    "ldmia",          // ARMV5_LDMIA
    "ldmib",          // ARMV5_LDMIB
    "ldmda",          // ARMV5_LDMDA
    "ldmdb",          // ARMV5_LDMDB
    "stm",            // ARMV5_STM
    "stmia",          // ARMV5_STMIA
    "stmib",          // ARMV5_STMIB
    "stmda",          // ARMV5_STMDA
    "stmdb",          // ARMV5_STMDB
    "push",           // ARMV5_PUSH
    "pop",            // ARMV5_POP
    /* Swap */
    "swp",            // ARMV5_SWP
    "swpb",           // ARMV5_SWPB
    /* Software Interrupt */
    "swi",            // ARMV5_SWI
    "svc",            // ARMV5_SVC
    "bkpt",           // ARMV5_BKPT
    /* Coprocessor */
    "cdp",            // ARMV5_CDP
    "ldc",            // ARMV5_LDC
    "stc",            // ARMV5_STC
    "mcr",            // ARMV5_MCR
    "mrc",            // ARMV5_MRC
    "mcrr",           // ARMV5_MCRR
    "mrrc",           // ARMV5_MRRC
    /* Status Register */
    "mrs",            // ARMV5_MRS
    "msr",            // ARMV5_MSR
    /* Preload (ARMv5TE) */
    "pld",            // ARMV5_PLD
    /* VFPv2 Instructions */
    "vmov",           // ARMV5_VMOV
    "vadd",           // ARMV5_VADD
    "vsub",           // ARMV5_VSUB
    "vmul",           // ARMV5_VMUL
    "vnmul",          // ARMV5_VNMUL
    "vmla",           // ARMV5_VMLA
    "vmls",           // ARMV5_VMLS
    "vdiv",           // ARMV5_VDIV
    "vneg",           // ARMV5_VNEG
    "vabs",           // ARMV5_VABS
    "vsqrt",          // ARMV5_VSQRT
    "vcmp",           // ARMV5_VCMP
    "vcmpe",          // ARMV5_VCMPE
    "vcvt",           // ARMV5_VCVT
    "vldr",           // ARMV5_VLDR
    "vstr",           // ARMV5_VSTR
    "vldm",           // ARMV5_VLDM
    "vstm",           // ARMV5_VSTM
    "vpush",          // ARMV5_VPUSH
    "vpop",           // ARMV5_VPOP
    "vmrs",           // ARMV5_VMRS
    "vmsr",           // ARMV5_VMSR
    "fmstat",         // ARMV5_FMSTAT
    /* Pseudo-ops */
    "nop",            // ARMV5_NOP
    "udf"             // ARMV5_UDF
};

static const char* condString[] = {
    "eq",
    "ne",
    "hs", /* cs */
    "lo", /* cc */
    "mi",
    "pl",
    "vs",
    "vc",
    "hi",
    "ls",
    "ge",
    "lt",
    "gt",
    "le",
    "", /* COND_AL */
    ""  /* COND_NV */
};

static const char* registerString[] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
    "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
    "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
    "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
    "cpsr", "cpsr_c", "cpsr_x", "cpsr_xc", "cpsr_s", "cpsr_sc", "cpsr_sx", "cpsr_sxc",
    "cpsr_f", "cpsr_fc", "cpsr_fx", "cpsr_fxc", "cpsr_fs", "cpsr_fsc", "cpsr_fsx", "cpsr_fsxc",
    "spsr", "spsr_c", "spsr_x", "spsr_xc", "spsr_s", "spsr_sc", "spsr_sx", "spsr_sxc",
    "spsr_f", "spsr_fc", "spsr_fx", "spsr_fxc", "spsr_fs", "spsr_fsc", "spsr_fsx", "spsr_fsxc",
    "fpsid", "fpscr", "fpexc"
};

static const char* shiftString[] = {
    "", /* SHIFT_NONE */
    "lsl",
    "lsr",
    "asr",
    "ror",
    "rrx"
};

static const char* coprocRegisterCString[] = {
    "c0",
    "c1",
    "c2",
    "c3",
    "c4",
    "c5",
    "c6",
    "c7",
    "c8",
    "c9",
    "c10",
    "c11",
    "c12",
    "c13",
    "c14",
    "c15",
};

static const char* coprocRegisterString[] = {
    "p0",
    "p1",
    "p2",
    "p3",
    "p4",
    "p5",
    "p6",
    "p7",
    "p8",
    "p9",
    "p10",
    "p11",
    "p12",
    "p13",
    "p14",
    "p15",
};

const char* get_operation(enum Operation operation) {
    if (operation < ARMV5_END_OPERATION)
        return operationString[operation];
    return "???";
}

const char* get_condition(enum Condition cond) {
    if (cond <= COND_NV)
        return condString[cond];
    return "??";
}

const char *get_register_name(enum Register reg)
{
    if ((unsigned)reg < REG_INVALID)
        return registerString[reg];

    // BN temporary/SSA register IDs come through here.
    // Use a small rotating buffer so it's safe even with multiple calls per line.
    static char buf[8][16];
    static int idx = 0;
    idx = (idx + 1) & 7;

    snprintf(buf[idx], sizeof(buf[idx]), "tmp_%u", (unsigned)reg);
    return buf[idx];
}

const char* get_shift(enum Shift shift) {
    if (shift <= SHIFT_RRX)
        return shiftString[shift];
    return "???";
}

uint32_t get_register_size(enum Register reg) {
    /* General purpose (r0-r15) and VFP single-precision (s0-s31) are 4 bytes */
    if (reg <= REG_S31)
        return 4;
    /* VFP double-precision (d0-d15) are 8 bytes */
    else if (reg <= REG_D15)
        return 8;
    /* Everything else defaults to 4 bytes */
    return 4;
}

/* Helper to extract bit field */
static inline uint32_t bits(uint32_t val, int hi, int lo) {
    return (val >> lo) & ((1u << (hi - lo + 1)) - 1);
}

static inline uint32_t bit(uint32_t val, int n) {
    return (val >> n) & 1;
}

/* Rotate right */
static inline uint32_t ror32(uint32_t val, int amount) {
    if (amount == 0) return val;
    amount &= 31;
    return (val >> amount) | (val << (32 - amount));
}

/* Expand ARM immediate: 8-bit value rotated right by 2*rot */
static inline uint32_t expand_imm(uint32_t imm8, uint32_t rot) {
    return ror32(imm8, rot * 2);
}

/* Sign extend */
static inline int32_t sign_extend(uint32_t val, int nbits) {
    int32_t shift = 32 - nbits;
    return ((int32_t)(val << shift)) >> shift;
}

/* Decode immediate shift - matches ARMv7 DecodeImmShift */
static uint32_t DecodeImmShift(uint32_t type, uint32_t imm5, Shift* shift) {
    switch (type) {
        case 0:
            if (imm5 == 0) {
                *shift = SHIFT_NONE;
                return 0;
            }
            *shift = SHIFT_LSL;
            return imm5;
        case 1:
            *shift = SHIFT_LSR;
            return (imm5 == 0) ? 32 : imm5;
        case 2:
            *shift = SHIFT_ASR;
            return (imm5 == 0) ? 32 : imm5;
        case 3:
            if (imm5 == 0) {
                *shift = SHIFT_RRX;
                return 1;
            }
            *shift = SHIFT_ROR;
            return imm5;
    }
    *shift = SHIFT_NONE;
    return 0;
}

/* Decode register shift - matches ARMv7 DecodeRegisterShift */
static Shift DecodeRegisterShift(uint32_t type) {
    switch (type) {
        case 0: return SHIFT_LSL;
        case 1: return SHIFT_LSR;
        case 2: return SHIFT_ASR;
        case 3: return SHIFT_ROR;
    }
    return SHIFT_NONE;
}

uint32_t armv5_data_processing_reg(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t rm:4;
            uint32_t zero:1;
            uint32_t type:2;
            uint32_t imm5:5;
            uint32_t rd:4;
            uint32_t rn:4;
            uint32_t s:1;
            uint32_t op:4;
            uint32_t group:3;
            uint32_t cond:4;
        };
    } decode;

    static Operation operation[] = {
        ARMV5_AND, ARMV5_EOR, ARMV5_SUB, ARMV5_RSB,
        ARMV5_ADD, ARMV5_ADC, ARMV5_SBC, ARMV5_RSC,
        ARMV5_TST, ARMV5_TEQ, ARMV5_CMP, ARMV5_CMN,
        ARMV5_ORR, ARMV5_MOV, ARMV5_BIC, ARMV5_MVN
    };

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.cond;

    if (decode.zero != 0)
        return 1;
    if (decode.op >= 8 && decode.op <= 11 && decode.s == 0)
        return 1;

    /* Check for NOP: MOV Rd, Rd with no shift and no S flag
     * Canonical NOP is MOV R0, R0 (0xe1a00000) but any MOV Rx, Rx qualifies */
    if (decode.op == 13 && decode.rd == decode.rm && decode.imm5 == 0 &&
        decode.type == 0 && decode.s == 0)
    {
        instruction->operation = ARMV5_NOP;
        return 0;
    }

    instruction->operation = operation[decode.op];
    instruction->setsFlags = decode.s;

    uint32_t i = 0;

    /* Test ops (TST, TEQ, CMP, CMN) don't have Rd */
    if (decode.op < 8 || decode.op > 11) {
        instruction->operands[i].cls = REG;
        instruction->operands[i++].reg = (Register)decode.rd;
    } else {
        instruction->setsFlags = 0; /* Test ops always set flags, don't encode separately */
    }

    /* MOV and MVN don't use Rn */
    if (decode.op != 13 && decode.op != 15) {
        instruction->operands[i].cls = REG;
        instruction->operands[i++].reg = (Register)decode.rn;
    }

    instruction->operands[i].cls = REG;
    instruction->operands[i].reg = (Register)decode.rm;
    instruction->operands[i].imm = DecodeImmShift(decode.type, decode.imm5, &instruction->operands[i].shift);

    return 0;
}

uint32_t armv5_data_processing_imm(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t imm:12;
            uint32_t rd:4;
            uint32_t rn:4;
            uint32_t s:1;
            uint32_t op:4;
            uint32_t group:3;
            uint32_t cond:4;
        };
    } decode;

    static Operation operation[] = {
        ARMV5_AND, ARMV5_EOR, ARMV5_SUB, ARMV5_RSB,
        ARMV5_ADD, ARMV5_ADC, ARMV5_SBC, ARMV5_RSC,
        ARMV5_TST, ARMV5_TEQ, ARMV5_CMP, ARMV5_CMN,
        ARMV5_ORR, ARMV5_MOV, ARMV5_BIC, ARMV5_MVN
    };

    decode.value = instructionValue;
    if (decode.op >= 8 && decode.op <= 11 && decode.s == 0)
        return 1;
    instruction->operation = operation[decode.op];
    instruction->cond = (Condition)decode.cond;
    instruction->setsFlags = decode.s;

    uint32_t i = 0;

    /* Test ops don't write to Rd */
    if (decode.op < 8 || decode.op > 11) {
        instruction->operands[i].cls = REG;
        instruction->operands[i++].reg = (Register)decode.rd;
    } else {
        instruction->setsFlags = 0; /* Test ops always set flags, don't encode separately */
    }

    /* MOV and MVN don't use Rn */
    if (decode.op != 13 && decode.op != 15) {
        instruction->operands[i].cls = REG;
        instruction->operands[i++].reg = (Register)decode.rn;
    }

    instruction->operands[i].cls = IMM;
    instruction->operands[i].imm = expand_imm(decode.imm & 0xff, (decode.imm >> 8) & 0xf);

    return 0;
}

uint32_t armv5_multiply_and_accumulate(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t rn:4;
            uint32_t group1:4;
            uint32_t rm:4;
            uint32_t rdlo:4;
            uint32_t rdhi:4;
            uint32_t s:1;
            uint32_t op:3;
            uint32_t group2:4;
            uint32_t cond:4;
        };
    } decode;

    static Operation operation[] = {
        ARMV5_MUL, ARMV5_MLA, ARMV5_UNDEFINED, ARMV5_UNDEFINED,
        ARMV5_UMULL, ARMV5_UMLAL, ARMV5_SMULL, ARMV5_SMLAL
    };

    decode.value = instructionValue;
    instruction->operation = operation[decode.op];
    instruction->cond = (Condition)decode.cond;
    instruction->setsFlags = decode.s;

    if (instruction->operation == ARMV5_UNDEFINED)
        return 1;

    /* ARMv5 constraints: PC (r15) cannot be used in any operand position */
    if (decode.rn == 15 || decode.rm == 15 || decode.rdhi == 15)
        return 1;

    if (decode.op >= 4) {
        /* Long multiply additional constraints */
        if (decode.rdlo == 15)
            return 1;
        /* RdHi and RdLo must be different registers */
        if (decode.rdhi == decode.rdlo)
            return 1;
        /* Rd must not be the same as Rm (ARMv5 restriction, relaxed in ARMv6) */
        if (decode.rdhi == decode.rm || decode.rdlo == decode.rm)
            return 1;
    } else {
        /* Regular multiply: Rd must not equal Rm (ARMv5 restriction) */
        if (decode.rdhi == decode.rn)
            return 1;
    }

    uint32_t i = 0;

    if (decode.op >= 4) {
        /* Long multiply: RdLo, RdHi, Rm, Rn */
        instruction->operands[i].cls = REG;
        instruction->operands[i++].reg = (Register)decode.rdlo;
        instruction->operands[i].cls = REG;
        instruction->operands[i++].reg = (Register)decode.rdhi;
    } else {
        /* Regular multiply: Rd, Rm, Rs */
        instruction->operands[i].cls = REG;
        instruction->operands[i++].reg = (Register)decode.rdhi;
    }

    instruction->operands[i].cls = REG;
    instruction->operands[i++].reg = (Register)decode.rn;
    instruction->operands[i].cls = REG;
    instruction->operands[i++].reg = (Register)decode.rm;

    if (decode.op == 1) {
        /* MLA: add Rn */
        instruction->operands[i].cls = REG;
        instruction->operands[i].reg = (Register)decode.rdlo;
    }

    return 0;
}

uint32_t armv5_halfword_multiply_and_accumulate(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t rn:4;
            uint32_t group1:1;
            uint32_t x:1;
            uint32_t y:1;
            uint32_t one:1;
            uint32_t rm:4;
            uint32_t ra:4;
            uint32_t rd:4;
            uint32_t group2:1;
            uint32_t op:2;
            uint32_t group3:5;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.cond;

    /* ARMv5TE constraints: PC cannot be used in any operand position */
    if (decode.rd == 15 || decode.rn == 15 || decode.rm == 15 || decode.ra == 15)
        return 1;

    uint32_t i = 0;

    switch (decode.op) {
        case 0: /* SMLAxy */
            if (decode.x == 0 && decode.y == 0) instruction->operation = ARMV5_SMLABB;
            else if (decode.x == 1 && decode.y == 0) instruction->operation = ARMV5_SMLATB;
            else if (decode.x == 0 && decode.y == 1) instruction->operation = ARMV5_SMLABT;
            else instruction->operation = ARMV5_SMLATT;
            instruction->operands[i].cls = REG;
            instruction->operands[i++].reg = (Register)decode.rd;
            instruction->operands[i].cls = REG;
            instruction->operands[i++].reg = (Register)decode.rn;
            instruction->operands[i].cls = REG;
            instruction->operands[i++].reg = (Register)decode.rm;
            instruction->operands[i].cls = REG;
            instruction->operands[i].reg = (Register)decode.ra;
            break;

        case 1:
            if (decode.x == 0) {
                /* SMLAWy */
                if (decode.y == 0) instruction->operation = ARMV5_SMLAWB;
                else instruction->operation = ARMV5_SMLAWT;
                instruction->operands[i].cls = REG;
                instruction->operands[i++].reg = (Register)decode.rd;
                instruction->operands[i].cls = REG;
                instruction->operands[i++].reg = (Register)decode.rn;
                instruction->operands[i].cls = REG;
                instruction->operands[i++].reg = (Register)decode.rm;
                instruction->operands[i].cls = REG;
                instruction->operands[i].reg = (Register)decode.ra;
            } else {
                /* SMULWy */
                if (decode.y == 0) instruction->operation = ARMV5_SMULWB;
                else instruction->operation = ARMV5_SMULWT;
                instruction->operands[i].cls = REG;
                instruction->operands[i++].reg = (Register)decode.rd;
                instruction->operands[i].cls = REG;
                instruction->operands[i++].reg = (Register)decode.rn;
                instruction->operands[i].cls = REG;
                instruction->operands[i].reg = (Register)decode.rm;
            }
            break;

        case 2: /* SMLALxy */
            if (decode.x == 0 && decode.y == 0) instruction->operation = ARMV5_SMLALBB;
            else if (decode.x == 1 && decode.y == 0) instruction->operation = ARMV5_SMLALTB;
            else if (decode.x == 0 && decode.y == 1) instruction->operation = ARMV5_SMLALBT;
            else instruction->operation = ARMV5_SMLALTT;
            instruction->operands[i].cls = REG;
            instruction->operands[i++].reg = (Register)decode.ra; /* RdLo */
            instruction->operands[i].cls = REG;
            instruction->operands[i++].reg = (Register)decode.rd; /* RdHi */
            instruction->operands[i].cls = REG;
            instruction->operands[i++].reg = (Register)decode.rn;
            instruction->operands[i].cls = REG;
            instruction->operands[i].reg = (Register)decode.rm;
            break;

        case 3: /* SMULxy */
            if (decode.x == 0 && decode.y == 0) instruction->operation = ARMV5_SMULBB;
            else if (decode.x == 1 && decode.y == 0) instruction->operation = ARMV5_SMULTB;
            else if (decode.x == 0 && decode.y == 1) instruction->operation = ARMV5_SMULBT;
            else instruction->operation = ARMV5_SMULTT;
            instruction->operands[i].cls = REG;
            instruction->operands[i++].reg = (Register)decode.rd;
            instruction->operands[i].cls = REG;
            instruction->operands[i++].reg = (Register)decode.rn;
            instruction->operands[i].cls = REG;
            instruction->operands[i].reg = (Register)decode.rm;
            break;
    }

    return 0;
}

uint32_t armv5_saturating_add_sub(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t rm:4;
            uint32_t group1:8;
            uint32_t rd:4;
            uint32_t rn:4;
            uint32_t op:4;
            uint32_t group3:4;
            uint32_t cond:4;
        };
    } decode;

    static Operation operation[] = {
        ARMV5_QADD, ARMV5_QSUB, ARMV5_QDADD, ARMV5_QDSUB
    };

    decode.value = instructionValue;

    /* Validate op field - only bits 1 and 2 are used, bit 0 must be 0 */
    if (decode.op & 1)
        return 1;

    /* ARMv5TE constraints: PC cannot be used */
    if (decode.rd == 15 || decode.rm == 15 || decode.rn == 15)
        return 1;

    instruction->operation = operation[(decode.op >> 1) & 3];
    instruction->cond = (Condition)decode.cond;

    instruction->operands[0].cls = REG;
    instruction->operands[0].reg = (Register)decode.rd;
    instruction->operands[1].cls = REG;
    instruction->operands[1].reg = (Register)decode.rm;
    instruction->operands[2].cls = REG;
    instruction->operands[2].reg = (Register)decode.rn;

    return 0;
}

uint32_t armv5_branch(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    union {
        uint32_t value;
        struct {
            uint32_t imm24:24;
            uint32_t link:1;
            uint32_t group:3;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    instruction->operation = decode.link ? ARMV5_BL : ARMV5_B;
    instruction->cond = (Condition)decode.cond;

    int32_t offset = sign_extend(decode.imm24, 24) << 2;
    uint32_t target = address + 8 + offset;

    instruction->operands[0].cls = LABEL;
    instruction->operands[0].imm = target;

    return 0;
}

uint32_t armv5_branch_exchange(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t rm:4;
            uint32_t op:4;
            uint32_t group:20;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.cond;

    if (decode.group != 0x12fff)
        return 1;

    if (decode.op == 1) {
        instruction->operation = ARMV5_BX;
    } else if (decode.op == 3) {
        instruction->operation = ARMV5_BLX;
    } else {
        return 1;
    }

    if (decode.op == 3 && decode.rm == REG_PC)
        return 1;

    instruction->operands[0].cls = REG;
    instruction->operands[0].reg = (Register)decode.rm;

    return 0;
}

uint32_t armv5_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    union {
        uint32_t value;
        struct {
            uint32_t imm12:12;
            uint32_t rd:4;
            uint32_t rn:4;
            uint32_t l:1;
            uint32_t w:1;
            uint32_t b:1;
            uint32_t u:1;
            uint32_t p:1;
            uint32_t i:1;
            uint32_t group:2;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.cond;

    if (decode.rn == REG_PC && (!decode.p || decode.w))
        return 1;
    if (decode.i) {
        if (decode.imm12 & 0x10)
            return 1;
        if ((decode.imm12 & 0xf) == REG_PC)
            return 1;
    }

    if (decode.l) {
        instruction->operation = decode.b ? ARMV5_LDRB : ARMV5_LDR;
    } else {
        instruction->operation = decode.b ? ARMV5_STRB : ARMV5_STR;
    }

    instruction->operands[0].cls = REG;
    instruction->operands[0].reg = (Register)decode.rd;

    if (decode.p) {
        instruction->operands[1].cls = decode.w ? MEM_PRE_IDX : MEM_IMM;
    } else {
        instruction->operands[1].cls = MEM_POST_IDX;
    }
    instruction->operands[1].reg = (Register)decode.rn;
    instruction->operands[1].flags.add = decode.u;

    if (decode.i == 0) {
        /* Immediate offset */
        int32_t offset = decode.u ? (int32_t)decode.imm12 : -(int32_t)decode.imm12;

        /* For PC-relative loads, pre-compute the effective address.
         * Per ARMv5 spec (A5-20): "If R15 is specified as register Rn,
         * the value used is the address of the instruction plus eight."
         * Note: ARM instructions are always word-aligned, so no alignment needed. */
        if (decode.rn == REG_PC && decode.p && !decode.w) {
            uint32_t pc = address + 8;
            instruction->operands[1].cls = LABEL;
            instruction->operands[1].imm = pc + offset;
        } else {
            instruction->operands[1].imm = decode.imm12;
        }
    } else {
        /* Register offset */
        uint32_t rm = decode.imm12 & 0xf;
        uint32_t shift_type = (decode.imm12 >> 5) & 3;
        uint32_t shift_imm = (decode.imm12 >> 7) & 0x1f;

        instruction->operands[1].offset = (Register)rm;
        instruction->operands[1].flags.offsetRegUsed = 1;
        instruction->operands[1].imm = DecodeImmShift(shift_type, shift_imm, &instruction->operands[1].shift);
    }

    return 0;
}

/* Extra load/store instructions */
uint32_t armv5_extra_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    union {
        uint32_t value;
        struct {
            uint32_t rm:4;
            uint32_t one:1;
            uint32_t sh:2;
            uint32_t one2:1;
            uint32_t imm_hi:4;
            uint32_t rd:4;
            uint32_t rn:4;
            uint32_t l:1;
            uint32_t w:1;
            uint32_t i:1;
            uint32_t u:1;
            uint32_t p:1;
            uint32_t group:3;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.cond;

    if (decode.one != 1 || decode.one2 != 1)
        return 1;
    if (decode.rn == REG_PC && (!decode.p || decode.w))
        return 1;
    /* Post-indexed (P=0) with W=1 is unpredictable */
    if (!decode.p && decode.w)
        return 1;
    if (!decode.i) {
        if (decode.imm_hi != 0)
            return 1;
        if (decode.rm == REG_PC)
            return 1;
    }

    /* Determine operation */
    if (decode.l) {
        switch (decode.sh) {
            case 1: instruction->operation = ARMV5_LDRH; break;
            case 2: instruction->operation = ARMV5_LDRSB; break;
            case 3: instruction->operation = ARMV5_LDRSH; break;
            default: return 1;
        }
    } else {
        switch (decode.sh) {
            case 1: instruction->operation = ARMV5_STRH; break;
            case 2: instruction->operation = ARMV5_LDRD; break;
            case 3: instruction->operation = ARMV5_STRD; break;
            default: return 1;
        }
    }

    if (instruction->operation == ARMV5_LDRD || instruction->operation == ARMV5_STRD) {
        uint32_t writeback = (!decode.p) || decode.w;
        if (decode.rd & 1)
            return 1;
        if (decode.rd >= REG_LR)
            return 1;
        if (writeback && (decode.rn == decode.rd || decode.rn == (decode.rd + 1)))
            return 1;
        if (!decode.i && (decode.rm == decode.rd || decode.rm == (decode.rd + 1)))
            return 1;
    }

    uint32_t i = 0;
    instruction->operands[i].cls = REG;
    instruction->operands[i++].reg = (Register)decode.rd;

    /* For LDRD/STRD, add second register */
    if (instruction->operation == ARMV5_LDRD || instruction->operation == ARMV5_STRD) {
        instruction->operands[i].cls = REG;
        instruction->operands[i++].reg = (Register)(decode.rd + 1);
    }

    if (decode.p) {
        instruction->operands[i].cls = decode.w ? MEM_PRE_IDX : MEM_IMM;
    } else {
        instruction->operands[i].cls = MEM_POST_IDX;
    }
    instruction->operands[i].reg = (Register)decode.rn;
    instruction->operands[i].flags.add = decode.u;

    if (decode.i) {
        /* Immediate offset */
        uint32_t imm8 = (decode.imm_hi << 4) | decode.rm;
        int32_t offset = decode.u ? (int32_t)imm8 : -(int32_t)imm8;

        if (decode.rn == REG_PC && decode.p && !decode.w) {
            /* PC-relative: Per ARMv5 spec (A5-35): "If R15 is specified as
             * register Rn, the value used is the address of the instruction
             * plus eight." ARM instructions are always word-aligned. */
            uint32_t pc = address + 8;
            instruction->operands[i].cls = LABEL;
            instruction->operands[i].imm = pc + offset;
        } else {
            instruction->operands[i].imm = imm8;
        }
    } else {
        /* Register offset */
        instruction->operands[i].offset = (Register)decode.rm;
        instruction->operands[i].flags.offsetRegUsed = 1;
    }

    return 0;
}

/* Load/store multiple */
uint32_t armv5_load_store_multiple(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t reglist:16;
            uint32_t rn:4;
            uint32_t l:1;
            uint32_t w:1;
            uint32_t s:1;
            uint32_t u:1;
            uint32_t p:1;
            uint32_t group:3;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.cond;

    /* Determine addressing mode */
    if (decode.l) {
        if (decode.u && !decode.p) instruction->operation = ARMV5_LDMIA;
        else if (decode.u && decode.p) instruction->operation = ARMV5_LDMIB;
        else if (!decode.u && !decode.p) instruction->operation = ARMV5_LDMDA;
        else instruction->operation = ARMV5_LDMDB;

        /* Special case: POP (even with S bit - we show POP {reg}^ like IDA) */
        if (decode.rn == REG_SP && decode.u && !decode.p && decode.w) {
            instruction->operation = ARMV5_POP;
        }
    } else {
        if (decode.u && !decode.p) instruction->operation = ARMV5_STMIA;
        else if (decode.u && decode.p) instruction->operation = ARMV5_STMIB;
        else if (!decode.u && !decode.p) instruction->operation = ARMV5_STMDA;
        else instruction->operation = ARMV5_STMDB;

        /* Special case: PUSH (even with S bit - we show PUSH {reg}^ like IDA) */
        if (decode.rn == REG_SP && !decode.u && decode.p && decode.w) {
            instruction->operation = ARMV5_PUSH;
        }
    }

    uint32_t i = 0;

    /* Add base register (unless PUSH/POP) */
    if (instruction->operation != ARMV5_PUSH && instruction->operation != ARMV5_POP) {
        instruction->operands[i].cls = REG;
        instruction->operands[i].reg = (Register)decode.rn;
        instruction->operands[i++].flags.wb = decode.w;
    }

    /* Add register list */
    instruction->operands[i].cls = REG_LIST;
    instruction->operands[i].imm = decode.reglist;
    /* S bit indicates ^ suffix (user mode registers / exception return) */
    instruction->operands[i].flags.wb = decode.s;

    return 0;
}

/* Synchronization primitives (SWP/SWPB) */
uint32_t armv5_synchronization_primitives(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t rm:4;
            uint32_t group1:8;
            uint32_t rd:4;
            uint32_t rn:4;
            uint32_t group2:2;
            uint32_t b:1;
            uint32_t group3:5;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    if (decode.group1 != 0x09 || decode.group2 != 0 || decode.group3 != 0x02)
        return 1;
    if (decode.rd == REG_PC || decode.rn == REG_PC || decode.rm == REG_PC)
        return 1;
    instruction->operation = decode.b ? ARMV5_SWPB : ARMV5_SWP;
    instruction->cond = (Condition)decode.cond;

    instruction->operands[0].cls = REG;
    instruction->operands[0].reg = (Register)decode.rd;
    instruction->operands[1].cls = REG;
    instruction->operands[1].reg = (Register)decode.rm;
    instruction->operands[2].cls = MEM_IMM;
    instruction->operands[2].reg = (Register)decode.rn;
    instruction->operands[2].imm = 0;

    return 0;
}

/* Software interrupt */
uint32_t armv5_swi(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t imm24:24;
            uint32_t group:4;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    instruction->operation = ARMV5_SVC;
    instruction->cond = (Condition)decode.cond;

    instruction->operands[0].cls = IMM;
    instruction->operands[0].imm = decode.imm24;

    return 0;
}

/* MRS */
uint32_t armv5_mrs(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t group1:12;
            uint32_t rd:4;
            uint32_t group2:6;
            uint32_t r:1;
            uint32_t group3:5;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    if (decode.group1 != 0 || decode.group2 != 0x0f || decode.group3 != 0x02)
        return 1;
    if (decode.rd == REG_PC)
        return 1;
    instruction->operation = ARMV5_MRS;
    instruction->cond = (Condition)decode.cond;

    instruction->operands[0].cls = REG;
    instruction->operands[0].reg = (Register)decode.rd;
    instruction->operands[1].cls = REG;
    instruction->operands[1].reg = decode.r ? REGS_SPSR : REGS_CPSR;

    return 0;
}

/* MSR */
uint32_t armv5_msr(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t imm12:12;
            uint32_t group1:4;
            uint32_t mask:4;
            uint32_t group2:2;
            uint32_t r:1;
            uint32_t group3:2;
            uint32_t i:1;
            uint32_t group4:2;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    if (decode.i != 0)
        return 1;
    if (decode.group1 != 0xf || decode.group2 != 0x2 || decode.group3 != 0x2 || decode.group4 != 0)
        return 1;
    if ((decode.imm12 & 0xff0) != 0)
        return 1;
    if (decode.mask == 0)
        return 1;
    instruction->operation = ARMV5_MSR;
    instruction->cond = (Condition)decode.cond;

    /* Determine CPSR/SPSR variant based on mask */
    Register psr = decode.r ? REGS_SPSR : REGS_CPSR;
    if (decode.mask == 0x1) psr = decode.r ? REGS_SPSR_C : REGS_CPSR_C;
    else if (decode.mask == 0x2) psr = decode.r ? REGS_SPSR_X : REGS_CPSR_X;
    else if (decode.mask == 0x3) psr = decode.r ? REGS_SPSR_XC : REGS_CPSR_XC;
    else if (decode.mask == 0x4) psr = decode.r ? REGS_SPSR_S : REGS_CPSR_S;
    else if (decode.mask == 0x8) psr = decode.r ? REGS_SPSR_F : REGS_CPSR_F;
    else if (decode.mask == 0x9) psr = decode.r ? REGS_SPSR_FC : REGS_CPSR_FC;
    else if (decode.mask == 0xf) psr = decode.r ? REGS_SPSR_FSXC : REGS_CPSR_FSXC;

    instruction->operands[0].cls = REG;
    instruction->operands[0].reg = psr;

    if (decode.i) {
        instruction->operands[1].cls = IMM;
        instruction->operands[1].imm = expand_imm(decode.imm12 & 0xff, (decode.imm12 >> 8) & 0xf);
    } else {
        instruction->operands[1].cls = REG;
        instruction->operands[1].reg = (Register)(decode.imm12 & 0xf);
    }

    return 0;
}

/* CLZ */
uint32_t armv5_clz(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t rm:4;
            uint32_t group1:8;
            uint32_t rd:4;
            uint32_t group2:12;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    if (decode.group1 != 0xf1 || decode.group2 != 0x16f)
        return 1;
    if (decode.rd == REG_PC || decode.rm == REG_PC)
        return 1;
    instruction->operation = ARMV5_CLZ;
    instruction->cond = (Condition)decode.cond;

    instruction->operands[0].cls = REG;
    instruction->operands[0].reg = (Register)decode.rd;
    instruction->operands[1].cls = REG;
    instruction->operands[1].reg = (Register)decode.rm;

    return 0;
}

/* BKPT */
uint32_t armv5_bkpt(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t imm_lo:4;
            uint32_t group1:4;
            uint32_t imm_hi:12;
            uint32_t group2:8;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    if (decode.group1 != 0x7 || decode.group2 != 0x12 || decode.cond != COND_AL)
        return 1;
    instruction->operation = ARMV5_BKPT;
    instruction->cond = COND_AL; /* BKPT is always unconditional */

    instruction->operands[0].cls = IMM;
    instruction->operands[0].imm = (decode.imm_hi << 4) | decode.imm_lo;

    return 0;
}

/* 64-bit transfers between ARM core and extension registers (VFPv2) */
uint32_t armv5_64_bit_transfers(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    /* A7.9 64-bit transfers between ARM core and extension registers */
    (void)address;
    union {
        uint32_t value;
        struct {
            uint32_t group1:4;
            uint32_t one:1;
            uint32_t op:1;
            uint32_t zero:2;
            uint32_t c:1;
            uint32_t group2:17;
            uint32_t cond:4;
        } com;
        struct {
            uint32_t vm:4;
            uint32_t group1:1;
            uint32_t m:1;
            uint32_t group2:6;
            uint32_t rt:4;
            uint32_t rt2:4;
            uint32_t op:1;
            uint32_t group3:7;
            uint32_t cond:4;
        } vmov1;
    } decode;
    decode.value = instructionValue;
    if (decode.com.zero != 0 || decode.com.one != 1)
        return 1;

    instruction->operation = ARMV5_VMOV;
    instruction->cond = (Condition)decode.com.cond;
    if (decode.com.c == 0)
    {
        /* VMOV<c> <Sm>, <Sm1>, <Rt>, <Rt2> */
        /* VMOV<c> <Rt>, <Rt2>, <Sm>, <Sm1> */
        static uint8_t entries[2][4] = {{0,1,2,3}, {2,3,0,1}};
        instruction->operands[entries[decode.vmov1.op][0]].cls = REG;
        instruction->operands[entries[decode.vmov1.op][0]].reg = (Register)(REG_S0 + ((decode.vmov1.vm << 1) | decode.vmov1.m));
        instruction->operands[entries[decode.vmov1.op][1]].cls = REG;
        instruction->operands[entries[decode.vmov1.op][1]].reg = (Register)(REG_S0 + (((decode.vmov1.vm << 1) | decode.vmov1.m) + 1));
        instruction->operands[entries[decode.vmov1.op][2]].cls = REG;
        instruction->operands[entries[decode.vmov1.op][2]].reg = (Register)decode.vmov1.rt;
        instruction->operands[entries[decode.vmov1.op][3]].cls = REG;
        instruction->operands[entries[decode.vmov1.op][3]].reg = (Register)decode.vmov1.rt2;
    }
    else
    {
        /* VMOV<c> <Dm>, <Rt>, <Rt2> */
        /* VMOV<c> <Rt>, <Rt2>, <Dm> */
        static uint8_t entries[2][3] = {{0,1,2}, {2,0,1}};
        instruction->operands[entries[decode.vmov1.op][0]].cls = REG;
        instruction->operands[entries[decode.vmov1.op][0]].reg = (Register)(REG_D0 + ((decode.vmov1.m << 4) | decode.vmov1.vm));
        instruction->operands[entries[decode.vmov1.op][1]].cls = REG;
        instruction->operands[entries[decode.vmov1.op][1]].reg = (Register)decode.vmov1.rt;
        instruction->operands[entries[decode.vmov1.op][2]].cls = REG;
        instruction->operands[entries[decode.vmov1.op][2]].reg = (Register)decode.vmov1.rt2;
    }
    return instruction->operation == ARMV5_UNDEFINED;
}

/* Data processing (register-shifted register) */
uint32_t armv5_data_processing_reg_shifted_reg(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    /* A5.2.2 Data-processing (register-shifted register) */
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t rm:4;
            uint32_t group1:1;
            uint32_t type:2;
            uint32_t zero:1;
            uint32_t rs:4;
            uint32_t rd:4;
            uint32_t rn:4;
            uint32_t s:1;
            uint32_t op:4;
            uint32_t group2:3;
            uint32_t cond:4;
        };
    } decode;

    static Operation operation[] = {
        ARMV5_AND, ARMV5_EOR, ARMV5_SUB, ARMV5_RSB,
        ARMV5_ADD, ARMV5_ADC, ARMV5_SBC, ARMV5_RSC,
        ARMV5_TST, ARMV5_TEQ, ARMV5_CMP, ARMV5_CMN,
        ARMV5_ORR, ARMV5_MOV, ARMV5_BIC, ARMV5_MVN
    };

    decode.value = instructionValue;
    instruction->operation = operation[decode.op];
    instruction->cond = (Condition)decode.cond;
    instruction->setsFlags = decode.s;

    uint32_t i = 0;

    /* Test ops (TST, TEQ, CMP, CMN) don't have Rd */
    if (decode.op < 8 || decode.op > 11) {
        instruction->operands[i].cls = REG;
        instruction->operands[i++].reg = (Register)decode.rd;
    } else {
        instruction->setsFlags = 0; /* Test ops always set flags, don't encode separately */
    }

    /* MOV and MVN don't use Rn */
    if (decode.op != 13 && decode.op != 15) {
        instruction->operands[i].cls = REG;
        instruction->operands[i++].reg = (Register)decode.rn;
    }

    instruction->operands[i].cls = REG;
    instruction->operands[i].reg = (Register)decode.rm;
    instruction->operands[i].shift = DecodeRegisterShift(decode.type);
    instruction->operands[i].offset = (Register)decode.rs;
    instruction->operands[i].flags.offsetRegUsed = 1;

    return 0;
}

/* Extension register load/store (VFPv2) */
uint32_t armv5_extension_register_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    /* A7.6 Extension register load/store instructions */
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t imm8:8;
            uint32_t group1:4;
            uint32_t vd:4;
            uint32_t rn:4;
            uint32_t opcode:4;
            uint32_t group2:4;
            uint32_t cond:4;
        } com;
        struct {
            uint32_t imm8:8;
            uint32_t group1:4;
            uint32_t vd:4;
            uint32_t rn:4;
            uint32_t l:1;
            uint32_t w:1;
            uint32_t d:1;
            uint32_t u:1;
            uint32_t p:1;
            uint32_t group2:3;
            uint32_t cond:4;
        } vldr;
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.com.cond;

    uint32_t p = decode.vldr.p;
    uint32_t u = decode.vldr.u;
    uint32_t w = decode.vldr.w;
    uint32_t l = decode.vldr.l;
    uint32_t d = decode.vldr.d;

    /* VLDR/VSTR single or double */
    if (p == 1 && w == 0) {
        /* VLDR or VSTR */
        uint32_t isDouble = (decode.value >> 8) & 1;
        instruction->operation = l ? ARMV5_VLDR : ARMV5_VSTR;

        instruction->operands[0].cls = REG;
        if (isDouble)
            instruction->operands[0].reg = (Register)(REG_D0 + ((d << 4) | decode.vldr.vd));
        else
            instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vldr.vd << 1) | d));

        instruction->operands[1].cls = MEM_IMM;
        instruction->operands[1].reg = (Register)decode.vldr.rn;
        instruction->operands[1].imm = decode.vldr.imm8 << 2;
        instruction->operands[1].flags.add = u;

        return 0;
    }

    /* VLDM/VSTM/VPUSH/VPOP */
    if (p == 0 || w == 1) {
        uint32_t isDouble = (decode.value >> 8) & 1;
        uint32_t regCount = isDouble ? (decode.vldr.imm8 / 2) : decode.vldr.imm8;

        if (decode.vldr.rn == 13 && w == 1) {
            /* VPUSH or VPOP */
            instruction->operation = l ? ARMV5_VPOP : ARMV5_VPUSH;
        } else {
            instruction->operation = l ? ARMV5_VLDM : ARMV5_VSTM;
            instruction->operands[0].cls = REG;
            instruction->operands[0].reg = (Register)decode.vldr.rn;
            instruction->operands[0].flags.wb = w;
        }

        /* Build register list as single operand (simplified) */
        uint32_t startReg;
        if (isDouble)
            startReg = REG_D0 + ((d << 4) | decode.vldr.vd);
        else
            startReg = REG_S0 + ((decode.vldr.vd << 1) | d);

        uint32_t opIdx = (instruction->operation == ARMV5_VPUSH || instruction->operation == ARMV5_VPOP) ? 0 : 1;
        instruction->operands[opIdx].cls = REG_LIST;
        instruction->operands[opIdx].imm = 0;
        for (uint32_t i = 0; i < regCount && i < 16; i++) {
            instruction->operands[opIdx].imm |= (1 << (startReg + i - (isDouble ? REG_D0 : REG_S0)));
        }

        return 0;
    }

    return 1;
}

/* Floating-point data processing (VFPv2) */
uint32_t armv5_floating_point_data_processing(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    /* A7.5 Floating-point data-processing instructions */
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t opc4:4;
            uint32_t group1:2;
            uint32_t opc3:2;
            uint32_t sz:1;
            uint32_t group2:7;
            uint32_t opc2:4;
            uint32_t opc1:4;
            uint32_t group3:4;
            uint32_t cond:4;
        } com;
        struct {
            uint32_t vm:4;
            uint32_t group1:1;
            uint32_t m:1;
            uint32_t op:1;
            uint32_t n:1;
            uint32_t sz:1;
            uint32_t group2:3;
            uint32_t vd:4;
            uint32_t vn:4;
            uint32_t group3:2;
            uint32_t d:1;
            uint32_t group4:5;
            uint32_t cond:4;
        } vmla;
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.com.cond;

    uint32_t opc1 = decode.com.opc1;
    uint32_t opc2 = decode.com.opc2;
    uint32_t opc3 = decode.com.opc3;
    uint32_t sz = decode.com.sz;

    /* Determine register indices based on single (sz=0) or double (sz=1) precision */
    Register vd, vn, vm;
    if (sz == 0) {
        /* Single precision */
        instruction->dataType = DT_F32;
        vd = (Register)(REG_S0 + ((decode.vmla.vd << 1) | decode.vmla.d));
        vn = (Register)(REG_S0 + ((decode.vmla.vn << 1) | decode.vmla.n));
        vm = (Register)(REG_S0 + ((decode.vmla.vm << 1) | decode.vmla.m));
    } else {
        /* Double precision */
        instruction->dataType = DT_F64;
        vd = (Register)(REG_D0 + ((decode.vmla.d << 4) | decode.vmla.vd));
        vn = (Register)(REG_D0 + ((decode.vmla.n << 4) | decode.vmla.vn));
        vm = (Register)(REG_D0 + ((decode.vmla.m << 4) | decode.vmla.vm));
    }

    if ((opc1 & 0xb) == 0) {
        /* VMLA, VMLS */
        instruction->operation = (decode.vmla.op == 0) ? ARMV5_VMLA : ARMV5_VMLS;
        instruction->operands[0].cls = REG;
        instruction->operands[0].reg = vd;
        instruction->operands[1].cls = REG;
        instruction->operands[1].reg = vn;
        instruction->operands[2].cls = REG;
        instruction->operands[2].reg = vm;
        return 0;
    }

    if ((opc1 & 0xb) == 2) {
        /* VMUL, VNMUL */
        instruction->operation = (decode.vmla.op == 0) ? ARMV5_VMUL : ARMV5_VNMUL;
        instruction->operands[0].cls = REG;
        instruction->operands[0].reg = vd;
        instruction->operands[1].cls = REG;
        instruction->operands[1].reg = vn;
        instruction->operands[2].cls = REG;
        instruction->operands[2].reg = vm;
        return 0;
    }

    if ((opc1 & 0xb) == 3) {
        /* VADD, VSUB */
        instruction->operation = (decode.vmla.op == 0) ? ARMV5_VADD : ARMV5_VSUB;
        instruction->operands[0].cls = REG;
        instruction->operands[0].reg = vd;
        instruction->operands[1].cls = REG;
        instruction->operands[1].reg = vn;
        instruction->operands[2].cls = REG;
        instruction->operands[2].reg = vm;
        return 0;
    }

    if ((opc1 & 0xb) == 8) {
        /* VDIV */
        instruction->operation = ARMV5_VDIV;
        instruction->operands[0].cls = REG;
        instruction->operands[0].reg = vd;
        instruction->operands[1].cls = REG;
        instruction->operands[1].reg = vn;
        instruction->operands[2].cls = REG;
        instruction->operands[2].reg = vm;
        return 0;
    }

    if ((opc1 & 0xb) == 0xb) {
        /* Other operations based on opc2 */
        switch (opc2) {
            case 0:
                /* VMOV immediate (opc3[0] == 0) is VFPv3 only, not available in VFPv2 */
                break;
            case 1:
                if ((opc3 & 1) == 1) {
                    /* VMOV register */
                    instruction->operation = ARMV5_VMOV;
                    instruction->operands[0].cls = REG;
                    instruction->operands[0].reg = vd;
                    instruction->operands[1].cls = REG;
                    instruction->operands[1].reg = vm;
                    return 0;
                } else {
                    /* VNEG */
                    instruction->operation = ARMV5_VNEG;
                    instruction->operands[0].cls = REG;
                    instruction->operands[0].reg = vd;
                    instruction->operands[1].cls = REG;
                    instruction->operands[1].reg = vm;
                    return 0;
                }
                break;
            case 4:
            case 5:
                /* VCMP, VCMPE */
                instruction->operation = ((opc2 & 1) == 0) ? ARMV5_VCMP : ARMV5_VCMPE;
                instruction->operands[0].cls = REG;
                instruction->operands[0].reg = vd;
                if ((opc3 & 1) == 0) {
                    instruction->operands[1].cls = REG;
                    instruction->operands[1].reg = vm;
                } else {
                    instruction->operands[1].cls = FIMM;
                    instruction->operands[1].immf = 0.0f;
                }
                return 0;
            case 7:
                if ((opc3 & 1) == 1) {
                    /* VCVT double/single */
                    instruction->operation = ARMV5_VCVT;
                    instruction->operands[0].cls = REG;
                    instruction->operands[0].reg = vd;
                    instruction->operands[1].cls = REG;
                    instruction->operands[1].reg = vm;
                    return 0;
                }
                break;
            case 8:
                /* VCVT integer to float */
                instruction->operation = ARMV5_VCVT;
                instruction->operands[0].cls = REG;
                instruction->operands[0].reg = vd;
                instruction->operands[1].cls = REG;
                instruction->operands[1].reg = vm;
                return 0;
            case 12:
            case 13:
                /* VCVT float to integer */
                instruction->operation = ARMV5_VCVT;
                instruction->operands[0].cls = REG;
                instruction->operands[0].reg = vd;
                instruction->operands[1].cls = REG;
                instruction->operands[1].reg = vm;
                return 0;
            default:
                break;
        }

        if (opc2 == 0 && (opc3 & 1) == 1) {
            /* VABS */
            instruction->operation = ARMV5_VABS;
            instruction->operands[0].cls = REG;
            instruction->operands[0].reg = vd;
            instruction->operands[1].cls = REG;
            instruction->operands[1].reg = vm;
            return 0;
        }

        if (opc2 == 1 && (opc3 & 1) == 1) {
            /* VSQRT */
            instruction->operation = ARMV5_VSQRT;
            instruction->operands[0].cls = REG;
            instruction->operands[0].reg = vd;
            instruction->operands[1].cls = REG;
            instruction->operands[1].reg = vm;
            return 0;
        }
    }

    return 1;
}

/* Miscellaneous instructions */
uint32_t armv5_miscellaneous(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    /* A5.2.12 Miscellaneous instructions */
    union {
        uint32_t value;
        struct {
            uint32_t group1:4;
            uint32_t op2:3;
            uint32_t group2:2;
            uint32_t b:1;
            uint32_t group3:6;
            uint32_t op1:4;
            uint32_t group4:1;
            uint32_t op:2;
            uint32_t group5:5;
            uint32_t cond:4;
        };
        struct {
            uint32_t imm4:4;
            uint32_t group1:4;
            uint32_t imm12:12;
            uint32_t group2:12;
        } bkpt_set;
        struct {
            uint32_t rm:4;
            uint32_t group1:8;
            uint32_t rd:4;
            uint32_t group2:12;
            uint32_t cond:4;
        } clz;
        struct {
            uint32_t rm:4;
            uint32_t group1:28;
        } bx;
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.cond;

    switch (decode.op2) {
        case 0:
            /* MRS or MSR (register) */
            if ((decode.op & 1) == 0) {
                return armv5_mrs(instructionValue, instruction, address);
            } else {
                return armv5_msr(instructionValue, instruction, address);
            }
        case 1:
            if (decode.op == 1) {
                /* BX */
                return armv5_branch_exchange(instructionValue, instruction, address);
            } else if (decode.op == 3) {
                /* CLZ */
                return armv5_clz(instructionValue, instruction, address);
            }
            break;
        case 3:
            if (decode.op == 1) {
                /* BLX (register) */
                return armv5_branch_exchange(instructionValue, instruction, address);
            }
            break;
        case 5:
            /* Saturating add/subtract */
            return armv5_saturating_add_sub(instructionValue, instruction, address);
        case 7:
            /* BKPT */
            return armv5_bkpt(instructionValue, instruction, address);
        default:
            break;
    }

    return 1;
}

/* MSR immediate and hints */
uint32_t armv5_msr_imm_and_hints(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    /* A5.2.11 MSR (immediate), and hints */
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t imm12:12;
            uint32_t group1:4;
            uint32_t mask:4;
            uint32_t group2:2;
            uint32_t r:1;
            uint32_t group3:5;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.cond;

    if (decode.mask == 0) {
        /* Hints - NOP for ARMv5 */
        instruction->operation = ARMV5_NOP;
        return 0;
    }

    /* MSR immediate */
    instruction->operation = ARMV5_MSR;

    /* Determine the CPSR/SPSR variant with field mask */
    static Register cpsrRegs[16] = {
        REGS_CPSR, REGS_CPSR_C, REGS_CPSR_X, REGS_CPSR_XC,
        REGS_CPSR_S, REGS_CPSR_SC, REGS_CPSR_SX, REGS_CPSR_SXC,
        REGS_CPSR_F, REGS_CPSR_FC, REGS_CPSR_FX, REGS_CPSR_FXC,
        REGS_CPSR_FS, REGS_CPSR_FSC, REGS_CPSR_FSX, REGS_CPSR_FSXC
    };
    static Register spsrRegs[16] = {
        REGS_SPSR, REGS_SPSR_C, REGS_SPSR_X, REGS_SPSR_XC,
        REGS_SPSR_S, REGS_SPSR_SC, REGS_SPSR_SX, REGS_SPSR_SXC,
        REGS_SPSR_F, REGS_SPSR_FC, REGS_SPSR_FX, REGS_SPSR_FXC,
        REGS_SPSR_FS, REGS_SPSR_FSC, REGS_SPSR_FSX, REGS_SPSR_FSXC
    };

    instruction->operands[0].cls = SYS_REG;
    instruction->operands[0].reg = decode.r ? spsrRegs[decode.mask] : cpsrRegs[decode.mask];

    uint32_t imm8 = decode.imm12 & 0xff;
    uint32_t rot = (decode.imm12 >> 8) & 0xf;
    instruction->operands[1].cls = IMM;
    instruction->operands[1].imm = expand_imm(imm8, rot);

    return 0;
}

/* Transfers between ARM core and extension registers (single) */
uint32_t armv5_transfers(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    /* A7.8 8, 16, and 32-bit transfer between ARM core and extension registers */
    (void)address;

    union {
        uint32_t value;
        struct {
            uint32_t group1:4;
            uint32_t one:1;
            uint32_t op:1;
            uint32_t group2:2;
            uint32_t c:1;
            uint32_t group3:11;
            uint32_t l:1;
            uint32_t a:3;
            uint32_t group4:4;
            uint32_t cond:4;
        } com;
        struct {
            uint32_t vn:4;
            uint32_t group1:3;
            uint32_t n:1;
            uint32_t group2:4;
            uint32_t rt:4;
            uint32_t group3:4;
            uint32_t op:1;
            uint32_t group4:7;
            uint32_t cond:4;
        } vmov;
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.com.cond;

    if (decode.com.c == 0 && decode.com.a == 0) {
        /* VMOV (between ARM core register and single-precision) */
        instruction->operation = ARMV5_VMOV;
        Register sn = (Register)(REG_S0 + ((decode.vmov.vn << 1) | decode.vmov.n));

        if (decode.vmov.op == 0) {
            /* to floating-point */
            instruction->operands[0].cls = REG;
            instruction->operands[0].reg = sn;
            instruction->operands[1].cls = REG;
            instruction->operands[1].reg = (Register)decode.vmov.rt;
        } else {
            /* from floating-point */
            instruction->operands[0].cls = REG;
            instruction->operands[0].reg = (Register)decode.vmov.rt;
            instruction->operands[1].cls = REG;
            instruction->operands[1].reg = sn;
        }
        return 0;
    }

    if (decode.com.c == 0 && decode.com.a == 7) {
        /* VMRS or VMSR */
        if (decode.com.l == 1) {
            /* VMRS */
            uint32_t reg = (instructionValue >> 16) & 0xf;
            instruction->operation = ARMV5_VMRS;
            instruction->operands[0].cls = REG;
            if (decode.vmov.rt == 15) {
                instruction->operation = ARMV5_FMSTAT;
                return 0;
            }
            instruction->operands[0].reg = (Register)decode.vmov.rt;
            instruction->operands[1].cls = SYS_REG;
            if (reg == 1)
                instruction->operands[1].reg = REGS_FPSCR;
            else
                instruction->operands[1].reg = REG_INVALID;
            return 0;
        } else {
            /* VMSR */
            uint32_t reg = (instructionValue >> 16) & 0xf;
            instruction->operation = ARMV5_VMSR;
            instruction->operands[0].cls = SYS_REG;
            if (reg == 1)
                instruction->operands[0].reg = REGS_FPSCR;
            else
                instruction->operands[0].reg = REG_INVALID;
            instruction->operands[1].cls = REG;
            instruction->operands[1].reg = (Register)decode.vmov.rt;
            return 0;
        }
    }

    return 1;
}

/* Unconditional instructions (cond == 0xF) */
uint32_t armv5_unconditional(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address) {
    uint32_t op1 = (instructionValue >> 20) & 0xff;
    uint32_t op1_25_27 = (instructionValue >> 25) & 7;

    /* BLX immediate: op1[25:27] = 101 */
    if (op1_25_27 == 5) {
        int32_t offset = sign_extend(instructionValue & 0xffffff, 24) << 2;
        uint32_t h = (instructionValue >> 24) & 1;
        offset |= (h << 1);

        instruction->operation = ARMV5_BLX;
        instruction->cond = COND_AL;

        instruction->operands[0].cls = LABEL;
        instruction->operands[0].imm = address + 8 + offset;

        return 0;
    }

    /* PLD - Preload: op1[20:27] matches x1x1x101 */
    if ((op1 & 0xd7) == 0x55) {
        instruction->operation = ARMV5_PLD;
        instruction->cond = COND_AL;

        instruction->operands[0].cls = MEM_IMM;
        instruction->operands[0].reg = (Register)((instructionValue >> 16) & 0xf);
        instruction->operands[0].flags.add = (instructionValue >> 23) & 1;  /* U bit */

        if (((instructionValue >> 25) & 1) == 0) {
            /* Immediate offset */
            uint32_t imm12 = instructionValue & 0xfff;
            instruction->operands[0].imm = imm12;
        } else {
            /* Register offset */
            instruction->operands[0].offset = (Register)(instructionValue & 0xf);
            instruction->operands[0].flags.offsetRegUsed = 1;

            uint32_t shift_type = (instructionValue >> 5) & 3;
            uint32_t shift_imm = (instructionValue >> 7) & 0x1f;
            instruction->operands[0].imm = DecodeImmShift(shift_type, shift_imm, &instruction->operands[0].shift);
        }

        return 0;
    }

    /* Coprocessor instructions are valid with cond=0xF
     * Route to the coprocessor handler: op1[25:27] = 110 or 111 */
    if (op1_25_27 == 6 || op1_25_27 == 7) {
        /* Temporarily set condition to AL so coprocessor handler accepts it */
        uint32_t result = armv5_coprocessor_instruction_and_supervisor_call(instructionValue, instruction, address);
        if (result == 0) {
            instruction->cond = COND_AL;  /* Unconditional */
        }
        return result;
    }

    return 1;
}

/* Data processing and miscellaneous instructions */
uint32_t armv5_data_processing_and_misc(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    union {
        uint32_t value;
        struct {
            uint32_t group1:4;
            uint32_t op2:4;
            uint32_t group2:12;
            uint32_t op1:5;
            uint32_t op:1;
            uint32_t id:2;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.cond;

    if (decode.op == 0)
    {
        if ((decode.op1 & 0x19) == 0x10) /* 10xx0 */
        {
            if ((decode.op2 & 8) == 0)
            {
                /* Miscellaneous instructions - delegate to armv5_miscellaneous */
                return armv5_miscellaneous(instructionValue, instruction, address);
            }
            else if ((decode.op2 & 9) == 8)
            {
                /* Halfword multiply and accumulate */
                return armv5_halfword_multiply_and_accumulate(instructionValue, instruction, address);
            }
        }
        else /* !10xx0 */
        {
            if ((decode.op2 & 1) == 0)
            {
                return armv5_data_processing_reg(instructionValue, instruction, address);
            }
            else if ((decode.op2 & 9) == 1)
            {
                /* Data processing register-shifted register */
                return armv5_data_processing_reg_shifted_reg(instructionValue, instruction, address);
            }
        }

        if ((decode.op1 & 0x10) == 0 && decode.op2 == 9) /* 0xxxx */
            return armv5_multiply_and_accumulate(instructionValue, instruction, address);
        else if ((decode.op1 & 0x10) == 0x10 && decode.op2 == 9) /* 1xxxx */
            return armv5_synchronization_primitives(instructionValue, instruction, address);

        if ((decode.op1 & 0x12) != 0x02) /* !0xx1x */
        {
            if ((decode.op2 & 9) == 9)
                return armv5_extra_load_store(instructionValue, instruction, address);
        }

        if ((decode.op1 & 0x12) == 0x02) /* 0xx1x */
        {
            if ((decode.op2 & 9) == 9)
                return armv5_extra_load_store(instructionValue, instruction, address);
        }
    }
    else /* decode.op == 1 */
    {
        if ((decode.op1 & 0x19) == 0x10) /* 10xx0 */
        {
            /* MSR immediate or hints - delegate to armv5_msr_imm_and_hints */
            return armv5_msr_imm_and_hints(instructionValue, instruction, address);
        }
        return armv5_data_processing_imm(instructionValue, instruction, address);
    }

    instruction->operation = ARMV5_UNDEFINED;
    return 1;
}

/* Load/store word and unsigned byte */
uint32_t armv5_load_store_word_and_unsigned_byte(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    /* ARMv5 doesn't have media instructions, so all load/store word/byte go through armv5_load_store */
    return armv5_load_store(instructionValue, instruction, address);
}

/* Branch and block data transfer */
uint32_t armv5_branch_and_block_data_transfer(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    union {
        uint32_t value;
        struct {
            uint32_t group1:25;
            uint32_t op:1;
            uint32_t group2:2;
            uint32_t cond:4;
        };
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.cond;

    if (decode.op == 0)
    {
        return armv5_load_store_multiple(instructionValue, instruction, address);
    }
    else
    {
        return armv5_branch(instructionValue, instruction, address);
    }
}

/* Coprocessor instructions and supervisor call */
uint32_t armv5_coprocessor_instruction_and_supervisor_call(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
    /* A5.6 Coprocessor instructions, and Supervisor Call - matches ARMv7 pattern */
    union {
        uint32_t value;
        struct {
            uint32_t group1:4;
            uint32_t op:1;
            uint32_t group2:3;
            uint32_t coproc:4;
            uint32_t group3:4;
            uint32_t rn:4;
            uint32_t op1:6;
            uint32_t group4:2;
            uint32_t cond:4;
        } com;
        struct {
            uint32_t imm:24;
            uint32_t group1:4;
            uint32_t cond:4;
        } svc;
        struct {
            uint32_t imm8:8;
            uint32_t coproc:4;
            uint32_t crd:4;
            uint32_t rn:4;
            uint32_t l:1;
            uint32_t w:1;
            uint32_t n:1;
            uint32_t u:1;
            uint32_t p:1;
            uint32_t group:3;
            uint32_t cond:4;
        } stc;
        struct {
            uint32_t crm:4;
            uint32_t opc1:4;    /* bits 4-7 per ARM ARM */
            uint32_t coproc:4;
            uint32_t rt:4;
            uint32_t rt2:4;
            uint32_t group1:4;  /* bits 20-23 */
            uint32_t group2:4;  /* bits 24-27 */
            uint32_t cond:4;
        } mrrc;
        struct {
            uint32_t crm:4;
            uint32_t one:1;
            uint32_t opc2:3;
            uint32_t coproc:4;
            uint32_t rt:4;
            uint32_t crn:4;
            uint32_t group1:1;
            uint32_t opc1:3;
            uint32_t group2:4;
            uint32_t cond:4;
        } mcr;
        struct {
            uint32_t crm:4;
            uint32_t group1:1;
            uint32_t opc2:3;
            uint32_t coproc:4;
            uint32_t crd:4;
            uint32_t crn:4;
            uint32_t opc1:4;
            uint32_t group2:4;
            uint32_t cond:4;
        } cdp;
    } decode;

    decode.value = instructionValue;
    instruction->cond = (Condition)decode.com.cond;

    uint32_t op1 = decode.com.op1;

    /* SVC - op1[5:4] == 11 */
    if ((op1 >> 4) == 3) {
        if (decode.svc.group1 != 0xf)
            return 1;
        return armv5_swi(instructionValue, instruction, address);
    }

    /* Check for VFP coprocessor (p10/p11) */
    if ((decode.com.coproc >> 1) == 5) {
        if ((op1 & 0x30) == 0x20) {
            /* Data processing or transfers */
            if (decode.com.op == 0) {
                return armv5_floating_point_data_processing(instructionValue, instruction, address);
            } else {
                return armv5_transfers(instructionValue, instruction, address);
            }
        } else if (op1 == 4 || op1 == 5) {
            /* 64-bit transfers */
            return armv5_64_bit_transfers(instructionValue, instruction, address);
        } else {
            /* Extension register load/store */
            return armv5_extension_register_load_store(instructionValue, instruction, address);
        }
    }

    /* Generic coprocessor instructions */
    if ((op1 & 0x30) == 0x20) {
        /* op1 = 10xxxx: CDP, MCR, MRC */
        if (decode.com.op == 0) {
            if (decode.cdp.group1 != 0 || decode.cdp.group2 != 0xe)
                return 1;
            /* CDP */
            instruction->operation = ARMV5_CDP;
            instruction->operands[0].cls = REG_COPROCP;
            instruction->operands[0].reg = (Register)decode.cdp.coproc;
            instruction->operands[1].cls = COPROC_OPC;
            instruction->operands[1].imm = decode.cdp.opc1;
            instruction->operands[2].cls = REG_COPROCC;
            instruction->operands[2].reg = (Register)decode.cdp.crd;
            instruction->operands[3].cls = REG_COPROCC;
            instruction->operands[3].reg = (Register)decode.cdp.crn;
            instruction->operands[4].cls = REG_COPROCC;
            instruction->operands[4].reg = (Register)decode.cdp.crm;
            instruction->operands[5].cls = COPROC_OPC;
            instruction->operands[5].imm = decode.cdp.opc2;
        } else {
            if (decode.mcr.one != 1 || decode.mcr.group2 != 0xe)
                return 1;
            /* MCR/MRC */
            instruction->operation = (op1 & 1) ? ARMV5_MRC : ARMV5_MCR;
            if (!(op1 & 1) && decode.mcr.rt == REG_PC)
                return 1;
            instruction->operands[0].cls = REG_COPROCP;
            instruction->operands[0].reg = (Register)decode.mcr.coproc;
            instruction->operands[1].cls = COPROC_OPC;
            instruction->operands[1].imm = decode.mcr.opc1;
            instruction->operands[2].cls = REG;
            instruction->operands[2].reg = (Register)decode.mcr.rt;
            instruction->operands[3].cls = REG_COPROCC;
            instruction->operands[3].reg = (Register)decode.mcr.crn;
            instruction->operands[4].cls = REG_COPROCC;
            instruction->operands[4].reg = (Register)decode.mcr.crm;
            instruction->operands[5].cls = COPROC_OPC;
            instruction->operands[5].imm = decode.mcr.opc2;
        }
    } else if (op1 == 4) {
        /* MCRR: bits 27-20 = 11000100 (0xC4), group2=0xC, group1=0x4 */
        if (decode.mrrc.group2 != 0xC || decode.mrrc.group1 != 0x4)
            return 1;
        if (decode.mrrc.rt == REG_PC || decode.mrrc.rt2 == REG_PC)
            return 1;
        /* MCRR */
        instruction->operation = ARMV5_MCRR;
        instruction->operands[0].cls = REG_COPROCP;
        instruction->operands[0].reg = (Register)decode.mrrc.coproc;
        instruction->operands[1].cls = COPROC_OPC;
        instruction->operands[1].imm = decode.mrrc.opc1;
        instruction->operands[2].cls = REG;
        instruction->operands[2].reg = (Register)decode.mrrc.rt;
        instruction->operands[3].cls = REG;
        instruction->operands[3].reg = (Register)decode.mrrc.rt2;
        instruction->operands[4].cls = REG_COPROCC;
        instruction->operands[4].reg = (Register)decode.mrrc.crm;
    } else if (op1 == 5) {
        /* MRRC: bits 27-20 = 11000101 (0xC5), group2=0xC, group1=0x5 */
        if (decode.mrrc.group2 != 0xC || decode.mrrc.group1 != 0x5)
            return 1;
        if (decode.mrrc.rt == REG_PC || decode.mrrc.rt2 == REG_PC)
            return 1;
        /* MRRC */
        instruction->operation = ARMV5_MRRC;
        instruction->operands[0].cls = REG_COPROCP;
        instruction->operands[0].reg = (Register)decode.mrrc.coproc;
        instruction->operands[1].cls = COPROC_OPC;
        instruction->operands[1].imm = decode.mrrc.opc1;
        instruction->operands[2].cls = REG;
        instruction->operands[2].reg = (Register)decode.mrrc.rt;
        instruction->operands[3].cls = REG;
        instruction->operands[3].reg = (Register)decode.mrrc.rt2;
        instruction->operands[4].cls = REG_COPROCC;
        instruction->operands[4].reg = (Register)decode.mrrc.crm;
    } else if ((op1 & 0x21) == 0x00 && op1 != 0) {
        if (decode.stc.group != 6)
            return 1;
        if (decode.stc.rn == REG_PC && (!decode.stc.p || decode.stc.w))
            return 1;
        /* STC */
        instruction->operation = ARMV5_STC;
        instruction->operands[0].cls = REG_COPROCP;
        instruction->operands[0].reg = (Register)decode.stc.coproc;
        instruction->operands[1].cls = REG_COPROCC;
        instruction->operands[1].reg = (Register)decode.stc.crd;
        if (decode.stc.p == 1 && decode.stc.w == 0)
            instruction->operands[2].cls = MEM_IMM;
        else if (decode.stc.p == 1 && decode.stc.w == 1)
            instruction->operands[2].cls = MEM_PRE_IDX;
        else
            instruction->operands[2].cls = MEM_POST_IDX;
        instruction->operands[2].reg = (Register)decode.stc.rn;
        instruction->operands[2].imm = decode.stc.imm8 << 2;
        instruction->operands[2].flags.add = decode.stc.u;
    } else if ((op1 & 0x21) == 0x01 && op1 != 0) {
        if (decode.stc.group != 6)
            return 1;
        if (decode.stc.rn == REG_PC && (!decode.stc.p || decode.stc.w))
            return 1;
        /* LDC */
        instruction->operation = ARMV5_LDC;
        instruction->operands[0].cls = REG_COPROCP;
        instruction->operands[0].reg = (Register)decode.stc.coproc;
        instruction->operands[1].cls = REG_COPROCC;
        instruction->operands[1].reg = (Register)decode.stc.crd;
        if (decode.stc.p == 1 && decode.stc.w == 0)
            instruction->operands[2].cls = MEM_IMM;
        else if (decode.stc.p == 1 && decode.stc.w == 1)
            instruction->operands[2].cls = MEM_PRE_IDX;
        else
            instruction->operands[2].cls = MEM_POST_IDX;
        instruction->operands[2].reg = (Register)decode.stc.rn;
        instruction->operands[2].imm = decode.stc.imm8 << 2;
        instruction->operands[2].flags.add = decode.stc.u;
    } else {
        instruction->operation = ARMV5_UNDEFINED;
        return 1;
    }

    return 0;
}

/* Main ARM instruction decoder - matches ARMv7 pattern */
uint32_t armv5_decompose(
    uint32_t instructionValue,
    struct Instruction* restrict instruction,
    uint32_t address,
    uint32_t bigEndian)
{
    union {
        uint32_t value;
        struct {
            uint32_t group1:4;
            uint32_t op:1;
            uint32_t group2:20;
            uint32_t op1:3;
            uint32_t cond:4;
        };
    } decode;

    if (bigEndian)
        decode.value = bswap32(instructionValue);
    else
        decode.value = instructionValue;

    /* Decompose the instructionValue into its various groups */
    static armv5_decompose_instruction group[2][8][2] = {
        {
            {armv5_data_processing_and_misc, armv5_data_processing_and_misc},
            {armv5_data_processing_and_misc, armv5_data_processing_and_misc},
            {armv5_load_store_word_and_unsigned_byte, armv5_load_store_word_and_unsigned_byte},
            {armv5_load_store_word_and_unsigned_byte, armv5_load_store_word_and_unsigned_byte},
            {armv5_branch_and_block_data_transfer, armv5_branch_and_block_data_transfer},
            {armv5_branch_and_block_data_transfer, armv5_branch_and_block_data_transfer},
            {armv5_coprocessor_instruction_and_supervisor_call, armv5_coprocessor_instruction_and_supervisor_call},
            {armv5_coprocessor_instruction_and_supervisor_call, armv5_coprocessor_instruction_and_supervisor_call}
        },{
            {armv5_unconditional, armv5_unconditional},
            {armv5_unconditional, armv5_unconditional},
            {armv5_unconditional, armv5_unconditional},
            {armv5_unconditional, armv5_unconditional},
            {armv5_unconditional, armv5_unconditional},
            {armv5_unconditional, armv5_unconditional},
            {armv5_unconditional, armv5_unconditional},
            {armv5_unconditional, armv5_unconditional},
        }
    };
    return group[decode.cond == 15][decode.op1][decode.op](decode.value, instruction, address);
}

/* Helper: Get register list string for LDM/STM/PUSH/POP */
static uint32_t get_register_list(uint32_t regList, char* out, size_t outLength)
{
    if (out == NULL) return 1;

    char* end = out + outLength;
    out[0] = '\0';
    uint32_t first = 1;

    for (uint32_t i = 0; i < 16 && out < end; i++) {
        if (regList & (1 << i)) {
            if (first == 0)
                out += snprintf(out, end - out, ", ");
            first = 0;
            out += snprintf(out, end - out, "%s", get_register_name((Register)i));
        }
    }
    return 0;
}

/* Helper: Get full operation with condition and flags */
const char* get_data_type(DataType dt)
{
    static const char* dataTypes[] = {
        "",      /* DT_NONE */
        ".s8",   /* DT_S8 */
        ".s16",  /* DT_S16 */
        ".s32",  /* DT_S32 */
        ".s64",  /* DT_S64 */
        ".u8",   /* DT_U8 */
        ".u16",  /* DT_U16 */
        ".u32",  /* DT_U32 */
        ".u64",  /* DT_U64 */
        ".i8",   /* DT_I8 */
        ".i16",  /* DT_I16 */
        ".i32",  /* DT_I32 */
        ".i64",  /* DT_I64 */
        ".f16",  /* DT_F16 */
        ".f32",  /* DT_F32 */
        ".f64",  /* DT_F64 */
        ".8",    /* DT_8 */
        ".16",   /* DT_16 */
        ".32",   /* DT_32 */
        ".64",   /* DT_64 */
    };
    if (dt < DT_END) return dataTypes[dt];
    return "";
}

char* get_full_operation(char* outBuffer, size_t outBufferSize, Instruction* restrict instruction)
{
    static const char* setsFlags[2] = {"", "s"};

    snprintf(outBuffer, outBufferSize, "%s%s%s%s",
        get_operation(instruction->operation),
        get_data_type(instruction->dataType),
        setsFlags[instruction->setsFlags ? 1 : 0],
        get_condition(instruction->cond));

    return outBuffer;
}

/* Disassemble instruction to text */
uint32_t armv5_disassemble(
    struct Instruction* restrict instruction,
    char* outBuffer,
    uint32_t outBufferSize)
{
    char operands[512];
    char tmpOperand[256];
    static const char* neg[2] = {"-", ""};
    static const char* wb[2] = {"", "!"};
    static const char* crt[2] = {"", " ^"};
    memset(operands, 0, sizeof(operands));

    if (outBufferSize == 0) return 1;

    char* start = (char*)&operands;
    char* end = start + sizeof(operands);

    for (uint32_t i = 0; i < MAX_OPERANDS && instruction->operands[i].cls != NONE && start < end; i++)
    {
        InstructionOperand* op = &instruction->operands[i];
        if (i != 0)
            start += snprintf(start, end - start, ", ");

        switch (op->cls)
        {
        case REG:
            /* reg, reg <shift> imm, reg <shift> offset */
            if (op->shift == SHIFT_NONE)
            {
                start += snprintf(start, end - start, "%s%s", get_register_name(op->reg), wb[op->flags.wb]);
            }
            else if (op->flags.offsetRegUsed == 1)
            {
                /* Shifted by register */
                start += snprintf(start, end - start, "%s, %s %s",
                    get_register_name(op->reg),
                    get_shift(op->shift),
                    get_register_name(op->offset));
            }
            else
            {
                /* Shifted by immediate */
                if (op->shift == SHIFT_RRX)
                    start += snprintf(start, end - start, "%s, %s",
                        get_register_name(op->reg),
                        get_shift(op->shift));
                else if (op->imm != 0)
                    start += snprintf(start, end - start, "%s, %s #%#x",
                        get_register_name(op->reg),
                        get_shift(op->shift),
                        op->imm);
                else
                    start += snprintf(start, end - start, "%s", get_register_name(op->reg));
            }
            break;

        case REG_LIST:
            get_register_list(op->imm, tmpOperand, sizeof(tmpOperand));
            start += snprintf(start, end - start, "{%s}%s", tmpOperand, crt[op->flags.wb]);
            break;

        case IMM:
            start += snprintf(start, end - start, "#%#x", op->imm);
            break;

        case LABEL:
            start += snprintf(start, end - start, "%#x", op->imm);
            break;

        case SYS_REG:
            start += snprintf(start, end - start, "%s", get_register_name(op->reg));
            break;

        case MEM_PRE_IDX:
            if (op->flags.offsetRegUsed == 1)
            {
                if (op->imm == 0)
                    snprintf(tmpOperand, sizeof(tmpOperand), "%s", get_register_name(op->offset));
                else if (op->shift == SHIFT_RRX)
                    snprintf(tmpOperand, sizeof(tmpOperand), "%s, %s",
                        get_register_name(op->offset),
                        get_shift(op->shift));
                else
                    snprintf(tmpOperand, sizeof(tmpOperand), "%s, %s #%#x",
                        get_register_name(op->offset),
                        get_shift(op->shift),
                        op->imm);

                start += snprintf(start, end - start, "[%s, %s%s]!",
                    get_register_name(op->reg),
                    neg[op->flags.add == 1],
                    tmpOperand);
            }
            else
            {
                start += snprintf(start, end - start, "[%s, #%s%#x]!",
                    get_register_name(op->reg),
                    neg[op->flags.add == 1],
                    op->imm);
            }
            break;

        case MEM_POST_IDX:
            if (op->flags.offsetRegUsed == 1)
            {
                if (op->imm == 0)
                    snprintf(tmpOperand, sizeof(tmpOperand), "%s", get_register_name(op->offset));
                else if (op->shift == SHIFT_RRX)
                    snprintf(tmpOperand, sizeof(tmpOperand), "%s, %s",
                        get_register_name(op->offset),
                        get_shift(op->shift));
                else
                    snprintf(tmpOperand, sizeof(tmpOperand), "%s, %s #%#x",
                        get_register_name(op->offset),
                        get_shift(op->shift),
                        op->imm);

                start += snprintf(start, end - start, "[%s], %s%s",
                    get_register_name(op->reg),
                    neg[op->flags.add == 1],
                    tmpOperand);
            }
            else
            {
                start += snprintf(start, end - start, "[%s], #%s%#x",
                    get_register_name(op->reg),
                    neg[op->flags.add == 1],
                    op->imm);
            }
            break;

        case MEM_IMM:
        case MEM_REG:
            if (op->shift == SHIFT_NONE)
            {
                if (op->flags.offsetRegUsed == 1)
                {
                    start += snprintf(start, end - start, "[%s, %s%s]",
                        get_register_name(op->reg),
                        neg[op->flags.add == 1],
                        get_register_name(op->offset));
                }
                else
                {
                    if (op->imm != 0)
                        start += snprintf(start, end - start, "[%s, #%s%#x]",
                            get_register_name(op->reg),
                            neg[op->flags.add == 1],
                            op->imm);
                    else
                        start += snprintf(start, end - start, "[%s]", get_register_name(op->reg));
                }
            }
            else if (op->shift == SHIFT_RRX)
            {
                start += snprintf(start, end - start, "[%s, %s%s, %s]",
                    get_register_name(op->reg),
                    neg[op->flags.add == 1],
                    get_register_name(op->offset),
                    get_shift(op->shift));
            }
            else
            {
                start += snprintf(start, end - start, "[%s, %s%s, %s #%#x]",
                    get_register_name(op->reg),
                    neg[op->flags.add == 1],
                    get_register_name(op->offset),
                    get_shift(op->shift),
                    op->imm);
            }
            break;

        case COPROC:
            start += snprintf(start, end - start, "p%d", op->imm);
            break;

        case REG_COPROCP:
            start += snprintf(start, end - start, "p%d", op->reg);
            break;

        case REG_COPROCC:
            start += snprintf(start, end - start, "c%d", op->reg);
            break;

        case COPROC_OPC:
            /* Coprocessor opcode - printed as plain number without # prefix */
            start += snprintf(start, end - start, "%d", op->imm);
            break;

        case FIMM:
            /* Floating-point immediate (used for VCMP/VCMPE with zero) */
            start += snprintf(start, end - start, "#%.1f", (double)op->immf);
            break;

        default:
            return 4;
        }
    }

    snprintf(outBuffer, outBufferSize, "%s\t%s",
        get_full_operation(tmpOperand, sizeof(tmpOperand), instruction),
        operands);

    return 0;
}
