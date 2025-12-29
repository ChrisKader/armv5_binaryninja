/*
 * ARMv5 Intermediate Language (IL) Lifting Implementation
 *
 * Translates ARMv5 and Thumb instructions to Binary Ninja's Low-Level IL.
 * Follows the same patterns as the ARMv7 plugin in binaryninja-api/arch/armv7/.
 */

#include <stdarg.h>
#include <functional>
#include <map>
#include "il.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;
using namespace armv5;

/*
 * Detect ARM switch table pattern: ADD PC, PC, Rn followed by branch offsets.
 * Returns true if a switch table was detected, fills targets with destinations.
 */
static bool DetectSwitchTableFromIL(LowLevelILFunction& il, uint64_t addr,
    std::vector<uint64_t>& targets)
{
    Ref<Function> func = il.GetFunction();
    if (!func)
        return false;

    Ref<BinaryView> view = func->GetView();
    if (!view)
        return false;

    /* PC value at this instruction is addr + 8 (ARM pipeline) */
    uint64_t pcValue = addr + 8;

    /* Table should start at the next instruction */
    uint64_t tableBase = addr + 4;

    /*
     * Try to find bounds check before the jump.
     * Look for: CMP Rn, #max; BHI/BCS skip pattern
     * For now, scan up to 256 entries or until invalid.
     */
    const size_t maxEntries = 256;

    for (size_t i = 0; i < maxEntries; i++)
    {
        uint64_t entryAddr = tableBase + (i * 4);

        DataBuffer entryData = view->ReadBuffer(entryAddr, 4);
        if (entryData.GetLength() < 4)
            break;

        uint32_t offset = *(uint32_t*)entryData.GetData();

        /* Sanity check: offset should be reasonable (within 1MB) */
        if (offset > 0x100000)
            break;

        uint64_t target = pcValue + offset;

        if (!view->IsValidOffset(target))
            break;

        targets.push_back(target);
    }

    /* Need at least 2 entries to be a valid switch table */
    return targets.size() >= 2;
}

/* Macro to get register IL expression - uses proper register size */
#define ILREG(idx) il.Register(get_register_size(instr.operands[idx].reg), RegisterToIndex(instr.operands[idx].reg))
#define ILREG_DIRECT(reg) il.Register(get_register_size(reg), RegisterToIndex(reg))

/* Macro to create bitmask */
#define BITMASK(N, O) (((1ULL << (N)) - 1) << (O))

/* Register enum values match Binary Ninja register indices directly */
static inline uint32_t RegisterToIndex(Register reg) {
    return (uint32_t)reg;
}

/* Read register value, handling PC specially to return pointer for proper xref tracking.
 * ARM mode: PC reads as addr+8. Matches ARMv7 signature: takes InstructionOperand& */
static inline ExprId ReadRegisterOrPointer(LowLevelILFunction& il, const InstructionOperand& op, size_t addr) {
    if (op.reg == REG_PC)
        return il.ConstPointer(4, (addr + 8));
    return il.Register(get_register_size(op.reg), op.reg);
}

/* Overload for direct Register enum */
static inline ExprId ReadRegisterOrPointer(LowLevelILFunction& il, Register reg, uint64_t addr) {
    if (reg == REG_PC)
        return il.ConstPointer(4, addr + 8);
    return il.Register(get_register_size(reg), RegisterToIndex(reg));
}

/* Thumb version: PC reads as addr+4 */
static inline ExprId ReadRegisterOrPointerThumb(LowLevelILFunction& il, Register reg, uint64_t addr) {
    if (reg == REG_PC)
        return il.ConstPointer(4, addr + 4);
    return il.Register(get_register_size(reg), RegisterToIndex(reg));
}

/* Helper to count operands in instruction (find first NONE operand) */
static int GetOperandCount(const Instruction& instr) {
    for (int i = 0; i < MAX_OPERANDS; i++) {
        if (instr.operands[i].cls == NONE)
            return i;
    }
    return MAX_OPERANDS;
}

/* Get IL condition for ARM condition code */
ExprId GetCondition(LowLevelILFunction& il, uint32_t cond) {
    switch (cond) {
        case COND_EQ: return il.FlagCondition(LLFC_E);
        case COND_NE: return il.FlagCondition(LLFC_NE);
        case COND_CS: return il.FlagCondition(LLFC_UGE);
        case COND_CC: return il.FlagCondition(LLFC_ULT);
        case COND_MI: return il.FlagCondition(LLFC_NEG);
        case COND_PL: return il.FlagCondition(LLFC_POS);
        case COND_VS: return il.FlagCondition(LLFC_O);
        case COND_VC: return il.FlagCondition(LLFC_NO);
        case COND_HI: return il.FlagCondition(LLFC_UGT);
        case COND_LS: return il.FlagCondition(LLFC_ULE);
        case COND_GE: return il.FlagCondition(LLFC_SGE);
        case COND_LT: return il.FlagCondition(LLFC_SLT);
        case COND_GT: return il.FlagCondition(LLFC_SGT);
        case COND_LE: return il.FlagCondition(LLFC_SLE);
        case COND_AL:
        case COND_NV:
        default:
            return il.Const(1, 1);
    }
}

/* Execute IL conditionally - matches ARMv7 pattern */
static void ConditionExecute(LowLevelILFunction& il, Condition cond, ExprId trueCase) {
    if (UNCONDITIONAL(cond)) {
        il.AddInstruction(trueCase);
        return;
    }

    LowLevelILLabel trueLabel, falseLabel;
    il.AddInstruction(il.If(GetCondition(il, cond), trueLabel, falseLabel));
    il.MarkLabel(trueLabel);
    il.AddInstruction(trueCase);
    il.MarkLabel(falseLabel);
}

/* Direct jump - use existing label if available, otherwise jump to address */
static inline ExprId DirectJump(Architecture* arch, LowLevelILFunction& il, uint64_t target, size_t addrSize) {
    BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);
    if (label)
        return il.Goto(*label);
    else
        return il.Jump(il.ConstPointer(addrSize, target));
}

/* Conditional jump - handles all label combinations */
static void ConditionalJump(Architecture* arch, LowLevelILFunction& il, Condition cond, size_t addrSize, uint64_t t, uint64_t f) {
    BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
    BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);

    if (UNCONDITIONAL(cond)) {
        il.AddInstruction(DirectJump(arch, il, t, addrSize));
        return;
    }

    if (trueLabel && falseLabel) {
        il.AddInstruction(il.If(GetCondition(il, cond), *trueLabel, *falseLabel));
        return;
    }

    LowLevelILLabel trueCode, falseCode;

    if (trueLabel) {
        il.AddInstruction(il.If(GetCondition(il, cond), *trueLabel, falseCode));
        il.MarkLabel(falseCode);
        il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
        return;
    }

    if (falseLabel) {
        il.AddInstruction(il.If(GetCondition(il, cond), trueCode, *falseLabel));
        il.MarkLabel(trueCode);
        il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
        return;
    }

    il.AddInstruction(il.If(GetCondition(il, cond), trueCode, falseCode));
    il.MarkLabel(trueCode);
    il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
    il.MarkLabel(falseCode);
    il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
}

/* Lambda version of ConditionExecute for multi-instruction conditional blocks */
static void ConditionExecute(size_t addrSize, Condition cond, Instruction& instr, LowLevelILFunction& il,
    std::function<void (size_t addrSize, Instruction& instr, LowLevelILFunction& il)> conditionalCode)
{
    if (UNCONDITIONAL(cond))
    {
        conditionalCode(addrSize, instr, il);
        return;
    }

    LowLevelILLabel trueLabel, falseLabel;
    il.AddInstruction(il.If(GetCondition(il, cond), trueLabel, falseLabel));
    il.MarkLabel(trueLabel);
    conditionalCode(addrSize, instr, il);
    il.AddInstruction(il.Goto(falseLabel));
    il.MarkLabel(falseLabel);
}

/* Helper to count number of registers in a register list */
static uint32_t GetNumberOfRegs(uint32_t regList) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < 16; i++) {
        if (regList & (1 << i)) count++;
    }
    return count;
}

/* Read shifted register value */
static ExprId GetShiftedRegister(LowLevelILFunction& il, const Instruction& instr, int opIdx,
    uint64_t addr)
{
    const InstructionOperand& op = instr.operands[opIdx];
    uint32_t regSize = get_register_size(op.reg);
    ExprId reg = ReadRegisterOrPointer(il, op.reg, addr);

    if (op.shift == SHIFT_NONE) {
        return reg;
    }

    ExprId shiftAmount;
    if (op.flags.offsetRegUsed && op.offset != REG_INVALID) {
        /* Shift by register */
        uint32_t shiftRegSize = get_register_size(op.offset);
        shiftAmount = il.And(shiftRegSize, il.Register(shiftRegSize, RegisterToIndex(op.offset)), il.Const(1, 0xFF));
    } else {
        shiftAmount = il.Const(1, op.imm);
    }

    switch (op.shift) {
        case SHIFT_LSL:
            return il.ShiftLeft(regSize, reg, shiftAmount);
        case SHIFT_LSR:
            return il.LogicalShiftRight(regSize, reg, shiftAmount);
        case SHIFT_ASR:
            return il.ArithShiftRight(regSize, reg, shiftAmount);
        case SHIFT_ROR:
            return il.RotateRight(regSize, reg, shiftAmount);
        case SHIFT_RRX:
            /* Rotate right with extend (33-bit rotation through carry) */
            return il.Or(regSize,
                il.LogicalShiftRight(regSize, reg, il.Const(1, 1)),
                il.ShiftLeft(regSize, il.Flag(IL_FLAG_C), il.Const(1, regSize * 8 - 1)));
        default:
            return reg;
    }
}

/* Read operand value (ARM mode) - old signature for compatibility */
static ExprId ReadOperand(LowLevelILFunction& il, const Instruction& instr, int opIdx,
    uint64_t addr)
{
    const InstructionOperand& op = instr.operands[opIdx];

    switch (op.cls) {
        case REG:
            /* Use ReadRegisterOrPointer for proper PC handling */
            if (op.shift == SHIFT_NONE) {
                return ReadRegisterOrPointer(il, op.reg, addr);
            }
            return GetShiftedRegister(il, instr, opIdx, addr);

        case IMM:
            return il.Const(4, op.imm);

        case LABEL:
            /* Labels are code/data addresses - use ConstPointer for xref tracking */
            return il.ConstPointer(4, op.imm);

        default:
            return il.Undefined();
    }
}

/*
 * ReadILOperand - Read an instruction operand and return its IL expression
 *
 * This function translates ARM instruction operands into Binary Ninja IL expressions.
 * It handles the ARM flexible operand encoding (Operand2) which can be:
 *   - Immediate value (8-bit rotated by even amount)
 *   - Register optionally shifted by immediate or register
 *
 * Parameters:
 *   il        - The LLIL function builder
 *   op        - The operand to read (from decoded instruction)
 *   addr      - Current instruction address (for PC-relative calculations)
 *   isPointer - If true, use ConstPointer for immediates to enable xref tracking
 *
 * Returns: IL expression representing the operand's value
 *
 * ARM Operand2 encoding (bits [11:0] of data processing instructions):
 *   Immediate: bits[11:8] = rotate (multiply by 2), bits[7:0] = 8-bit immediate
 *   Register:  bits[11:4] = shift type/amount, bits[3:0] = Rm
 *
 * Shift types (bits[6:5]):
 *   00 = LSL (Logical Shift Left)
 *   01 = LSR (Logical Shift Right) - unsigned, fills with zeros
 *   10 = ASR (Arithmetic Shift Right) - signed, preserves sign bit
 *   11 = ROR (Rotate Right) or RRX if shift amount is 0
 *
 * Shift can be by:
 *   - Immediate 5-bit value (bits[11:7])
 *   - Register Rs (bits[11:8]), only bottom 8 bits used (masked with 0xFF)
 */
static ExprId ReadILOperand(LowLevelILFunction& il, InstructionOperand& op, size_t addr, bool isPointer = false)
{
    switch (op.cls) {
        case IMM:
        case LABEL:
            /*
             * Immediate operands: The disassembler pre-computes the rotated value.
             * LABEL is used for branch targets and PC-relative addresses where
             * the effective address has been pre-computed.
             *
             * Use ConstPointer for addresses to enable Binary Ninja's xref tracking.
             */
            if (isPointer)
                return il.ConstPointer(4, op.imm);
            return il.Const(4, op.imm);

        case REG:
            /*
             * Register operand: May include a shift operation.
             * ARM's flexible operand encoding allows Rm to be shifted.
             */
            if (op.shift == SHIFT_NONE)
                /* No shift - just read the register value (or PC+8 for PC) */
                return ReadRegisterOrPointer(il, op, addr);

            /* Shifted register: apply the shift operation to Rm */
            {
                uint32_t regSize = get_register_size(op.reg);
                ExprId reg = ReadRegisterOrPointer(il, op, addr);

                /*
                 * Determine shift amount:
                 * - If offsetRegUsed, shift amount comes from register Rs (bottom 8 bits)
                 * - Otherwise, shift amount is an immediate value
                 *
                 * Register shift: only bottom 8 bits used, hence mask with 0xFF
                 * This matches ARM behavior where Rs[7:0] specifies shift amount.
                 */
                ExprId shiftAmount;
                if (op.flags.offsetRegUsed && op.offset != REG_INVALID) {
                    uint32_t shiftRegSize = get_register_size(op.offset);
                    shiftAmount = il.And(shiftRegSize,
                        il.Register(shiftRegSize, op.offset),
                        il.Const(1, 0xFF));  /* Mask to 8 bits per ARM spec */
                } else {
                    shiftAmount = il.Const(1, op.imm);
                }

                switch (op.shift) {
                    case SHIFT_LSL:
                        /* Logical Shift Left: Rm << shift_amount */
                        return il.ShiftLeft(regSize, reg, shiftAmount);

                    case SHIFT_LSR:
                        /*
                         * Logical Shift Right: Rm >> shift_amount (unsigned)
                         * Zero-fills from the left. Used for unsigned division by 2^n.
                         */
                        return il.LogicalShiftRight(regSize, reg, shiftAmount);

                    case SHIFT_ASR:
                        /*
                         * Arithmetic Shift Right: Rm >> shift_amount (signed)
                         * Sign-extends from the left. Used for signed division by 2^n.
                         */
                        return il.ArithShiftRight(regSize, reg, shiftAmount);

                    case SHIFT_ROR:
                        /*
                         * Rotate Right: bits shifted out wrap around to the top.
                         * ROR by n: (Rm >> n) | (Rm << (32-n))
                         */
                        return il.RotateRight(regSize, reg, shiftAmount);

                    case SHIFT_RRX:
                        /*
                         * Rotate Right with Extend: 33-bit rotation through carry.
                         * Result = (C << 31) | (Rm >> 1)
                         * The old bit 0 of Rm becomes the new carry flag (handled elsewhere).
                         *
                         * This is used for multi-word shifts where carry propagates between words.
                         */
                        return il.Or(regSize,
                            il.LogicalShiftRight(regSize, reg, il.Const(1, 1)),
                            il.ShiftLeft(regSize, il.Flag(IL_FLAG_C), il.Const(1, regSize * 8 - 1)));

                    default:
                        return reg;
                }
            }

        case MEM_IMM:
        case MEM_PRE_IDX:
        case MEM_POST_IDX:
            /*
             * Memory operands should not be passed to ReadILOperand - they need
             * special handling via Load/Store operations. This is a programming error.
             */
        case NONE:
        default:
            return il.Unimplemented();
    }
}

/* Calculate memory address */
static ExprId GetMemoryAddress(LowLevelILFunction& il, const Instruction& instr, int opIdx,
    uint64_t addr, bool thumb = false)
{
    const InstructionOperand& op = instr.operands[opIdx];

    /* For LABEL operands (pre-computed PC-relative addresses), return directly */
    if (op.cls == LABEL) {
        return il.ConstPointer(4, op.imm);
    }

    /* Base register */
    ExprId base;
    if (op.reg == REG_PC) {
        uint32_t offset = thumb ? 4 : 8;
        /* Use ConstPointer for PC-relative to help BN track cross-references */
        base = il.ConstPointer(4, (addr + offset) & ~3ULL); /* Word-aligned */
    } else {
        base = il.Register(4, RegisterToIndex(op.reg));
    }

    /* Offset */
    ExprId offset;
    if (op.flags.offsetRegUsed && op.offset != REG_INVALID) {
        offset = il.Register(4, RegisterToIndex(op.offset));
        if (op.shift != SHIFT_NONE) {
            switch (op.shift) {
                case SHIFT_LSL:
                    offset = il.ShiftLeft(4, offset, il.Const(4, op.imm));
                    break;
                case SHIFT_LSR:
                    offset = il.LogicalShiftRight(4, offset, il.Const(4, op.imm));
                    break;
                case SHIFT_ASR:
                    offset = il.ArithShiftRight(4, offset, il.Const(4, op.imm));
                    break;
                case SHIFT_ROR:
                    offset = il.RotateRight(4, offset, il.Const(4, op.imm));
                    break;
                default:
                    break;
            }
        }
        if (!op.flags.add) {
            offset = il.Neg(4, offset);
        }
    } else {
        int32_t imm = (int32_t)op.imm;
        if (!op.flags.add) imm = -imm;
        offset = il.Const(4, imm);
    }

    /* Pre-indexed or offset addressing: address = base + offset */
    /* Post-indexed: address = base (offset applied after) */
    if (op.cls == MEM_POST_IDX) {
        return base;
    } else {
        return il.Add(4, base, offset);
    }
}

/* Write to register, handling PC writes as branches - matches ARMv7 signature */
static inline ExprId SetRegisterOrBranch(LowLevelILFunction& il, Register reg, ExprId value, uint32_t flags = 0)
{
    if (reg == REG_PC) {
        /* Note: flags are ignored for jumps - the Jump instruction doesn't set flags.
         * For MOVS PC, LR (return with SPSR restore), the flag setting happens in hardware
         * but Binary Ninja IL doesn't model this exactly. We just emit the jump. */
        return il.Jump(value);
    }
    return il.SetRegister(get_register_size(reg), reg, value, flags);
}

/* Get flag write type for operation */
static uint32_t GetFlagWriteType(const Instruction& instr) {
    if (!instr.setsFlags)
        return IL_FLAGWRITE_NONE;

    switch (instr.operation) {
        case ARMV5_ADD:
        case ARMV5_ADC:
        case ARMV5_SUB:
        case ARMV5_SBC:
        case ARMV5_RSB:
        case ARMV5_RSC:
        case ARMV5_CMP:
        case ARMV5_CMN:
            return IL_FLAGWRITE_NZCV;

        case ARMV5_AND:
        case ARMV5_EOR:
        case ARMV5_ORR:
        case ARMV5_BIC:
        case ARMV5_MOV:
        case ARMV5_MVN:
        case ARMV5_TST:
        case ARMV5_TEQ:
            /*
             * Per ARM spec, C may be modified by the shifter carry-out.
             * However, computing shifter carry correctly is complex and
             * Binary Ninja can't derive C from our IL expressions.
             * Following ARMv7 plugin pattern: only set N and Z flags.
             */
            return IL_FLAGWRITE_NZ;

        case ARMV5_MUL:
        case ARMV5_MLA:
            return IL_FLAGWRITE_NZ;

        default:
            return IL_FLAGWRITE_ALL;
    }
}

/* Lift ARM data processing instruction */
bool LiftDataProcessing(Architecture* arch, LowLevelILFunction& il,
    Instruction& instr, uint64_t addr)
{
    uint32_t flags = GetFlagWriteType(instr);
    ExprId result;

    switch (instr.operation) {
        case ARMV5_ADD:
            /* Standard ADD handling - switch tables handled in AnalyzeBasicBlocks */
            result = il.Add(4, ReadOperand(il, instr, 1, addr),
                ReadOperand(il, instr, 2, addr), flags);
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_ADC:
            result = il.AddCarry(4, ReadOperand(il, instr, 1, addr),
                ReadOperand(il, instr, 2, addr), il.Flag(IL_FLAG_C), flags);
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_SUB:
            result = il.Sub(4, ReadOperand(il, instr, 1, addr),
                ReadOperand(il, instr, 2, addr), flags);
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_SBC:
            result = il.SubBorrow(4, ReadOperand(il, instr, 1, addr),
                ReadOperand(il, instr, 2, addr),
                il.Not(1, il.Flag(IL_FLAG_C)), flags);
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_RSB:
            result = il.Sub(4, ReadOperand(il, instr, 2, addr),
                ReadOperand(il, instr, 1, addr), flags);
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_RSC:
            result = il.SubBorrow(4, ReadOperand(il, instr, 2, addr),
                ReadOperand(il, instr, 1, addr),
                il.Not(1, il.Flag(IL_FLAG_C)), flags);
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_AND:
            result = il.And(4, ReadOperand(il, instr, 1, addr),
                ReadOperand(il, instr, 2, addr), flags);
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_EOR:
            result = il.Xor(4, ReadOperand(il, instr, 1, addr),
                ReadOperand(il, instr, 2, addr), flags);
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_ORR:
            result = il.Or(4, ReadOperand(il, instr, 1, addr),
                ReadOperand(il, instr, 2, addr), flags);
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_BIC:
            result = il.And(4, ReadOperand(il, instr, 1, addr),
                il.Not(4, ReadOperand(il, instr, 2, addr)), flags);
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_MOV:
            result = ReadOperand(il, instr, 1, addr);
            if (instr.setsFlags) {
                result = il.And(4, result, il.Const(4, 0xFFFFFFFF), flags);
            }
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_MVN:
            result = il.Not(4, ReadOperand(il, instr, 1, addr));
            if (instr.setsFlags) {
                result = il.And(4, result, il.Const(4, 0xFFFFFFFF), flags);
            }
            ConditionExecute(il, instr.cond,
                SetRegisterOrBranch(il, instr.operands[0].reg, result));
            break;

        case ARMV5_CMP:
            ConditionExecute(il, instr.cond,
                il.Sub(4, ReadOperand(il, instr, 0, addr),
                    ReadOperand(il, instr, 1, addr), flags));
            break;

        case ARMV5_CMN:
            ConditionExecute(il, instr.cond,
                il.Add(4, ReadOperand(il, instr, 0, addr),
                    ReadOperand(il, instr, 1, addr), flags));
            break;

        case ARMV5_TST:
            ConditionExecute(il, instr.cond,
                il.And(4, ReadOperand(il, instr, 0, addr),
                    ReadOperand(il, instr, 1, addr), flags));
            break;

        case ARMV5_TEQ:
            ConditionExecute(il, instr.cond,
                il.Xor(4, ReadOperand(il, instr, 0, addr),
                    ReadOperand(il, instr, 1, addr), flags));
            break;

        default:
            return false;
    }

    return true;
}

/* Lift branch instructions */
bool LiftBranch(Architecture* arch, LowLevelILFunction& il,
    Instruction& instr, uint64_t addr, bool thumb)
{
    (void)thumb;
    size_t addrSize = 4;

    switch (instr.operation) {
        case ARMV5_B:
            ConditionalJump(arch, il, instr.cond, addrSize, instr.operands[0].imm, addr + 4);
            return false;  // ARMv7 returns false for B to indicate no fall-through

        case ARMV5_BL:
            ConditionExecute(il, instr.cond,
                il.Call(il.ConstPointer(4, instr.operands[0].imm)));
            break;

        case ARMV5_BLX:
            if (instr.operands[0].cls == LABEL) {
                ConditionExecute(il, instr.cond,
                    il.Call(il.ConstPointer(4, instr.operands[0].imm)));
            } else {
                ConditionExecute(il, instr.cond,
                    il.Call(ReadRegisterOrPointer(il, instr.operands[0].reg, addr)));
            }
            break;

        case ARMV5_BX:
            if (instr.operands[0].reg == REG_LR) {
                ConditionExecute(il, instr.cond,
                    il.Return(ReadRegisterOrPointer(il, instr.operands[0].reg, addr)));
            } else {
                /* Use TailCall for BX to non-LR register - typically a tail call pattern */
                ConditionExecute(il, instr.cond,
                    il.TailCall(ReadRegisterOrPointer(il, instr.operands[0].reg, addr)));
            }
            break;

        default:
            return false;
    }

    return true;
}

/* Lift load/store instructions */
bool LiftLoadStore(Architecture* arch, LowLevelILFunction& il,
    Instruction& instr, uint64_t addr, bool thumb)
{
    int memOpIdx = 1;
    size_t size = 4;
    bool signExtend = false;
    bool isLoad = true;

    switch (instr.operation) {
        case ARMV5_LDR:  size = 4; isLoad = true; break;
        case ARMV5_LDRB: size = 1; isLoad = true; break;
        case ARMV5_LDRH: size = 2; isLoad = true; break;
        case ARMV5_LDRSB: size = 1; isLoad = true; signExtend = true; break;
        case ARMV5_LDRSH: size = 2; isLoad = true; signExtend = true; break;
        case ARMV5_STR:  size = 4; isLoad = false; break;
        case ARMV5_STRB: size = 1; isLoad = false; break;
        case ARMV5_STRH: size = 2; isLoad = false; break;
        default:
            return false;
    }

    const InstructionOperand& memOp = instr.operands[memOpIdx];
    ExprId address = GetMemoryAddress(il, instr, memOpIdx, addr, thumb);

    if (isLoad) {

        ExprId value;
        if (signExtend) {
            value = il.SignExtend(4, il.Load(size, address));
        } else if (size < 4) {
            value = il.ZeroExtend(4, il.Load(size, address));
        } else {
            value = il.Load(size, address);
        }

        /* LDR does not set flags - pass 0 for flags parameter */
        ConditionExecute(il, instr.cond,
            SetRegisterOrBranch(il, instr.operands[0].reg, value, 0));
    } else {
        ExprId value = ILREG(0);
        if (size < 4) {
            value = il.LowPart(size, value);
        }
        ConditionExecute(il, instr.cond, il.Store(size, address, value));
    }

    /* Handle writeback
     * Pre-indexed (!): MEM_PRE_IDX - address already computed, write new base
     * Post-indexed: MEM_POST_IDX - need to compute new base (base + offset)
     * Offset only: MEM_IMM - no writeback
     */
    bool hasWriteback = (memOp.cls == MEM_PRE_IDX || memOp.cls == MEM_POST_IDX);
    if (hasWriteback && memOp.reg != REG_PC) {
        ExprId newBase;
        if (memOp.cls == MEM_PRE_IDX) {
            /* Pre-indexed: base + offset (same as address we used for load/store) */
            /* Recompute to avoid expression reuse issues */
            ExprId base = il.Register(4, RegisterToIndex(memOp.reg));
            ExprId offset;
            if (memOp.flags.offsetRegUsed && memOp.offset != REG_INVALID) {
                offset = il.Register(4, RegisterToIndex(memOp.offset));
                if (!memOp.flags.add) offset = il.Neg(4, offset);
            } else {
                int32_t imm = (int32_t)memOp.imm;
                if (!memOp.flags.add) imm = -imm;
                offset = il.Const(4, imm);
            }
            newBase = il.Add(4, base, offset);
        } else {
            /* Post-indexed: base + offset */
            ExprId offset;
            if (memOp.flags.offsetRegUsed && memOp.offset != REG_INVALID) {
                offset = il.Register(4, RegisterToIndex(memOp.offset));
                if (!memOp.flags.add) offset = il.Neg(4, offset);
            } else {
                int32_t imm = (int32_t)memOp.imm;
                if (!memOp.flags.add) imm = -imm;
                offset = il.Const(4, imm);
            }
            newBase = il.Add(4, il.Register(4, RegisterToIndex(memOp.reg)), offset);
        }
        ConditionExecute(il, instr.cond,
            il.SetRegister(4, RegisterToIndex(memOp.reg), newBase));
    }

    return true;
}

/* Lift LDRD/STRD - doubleword load/store */
bool LiftLoadStoreDouble(Architecture* arch, LowLevelILFunction& il,
    Instruction& instr, uint64_t addr, bool thumb)
{
    bool isLoad = (instr.operation == ARMV5_LDRD);
    int memOpIdx = 2;  // Memory operand is at index 2 for LDRD/STRD

    const InstructionOperand& memOp = instr.operands[memOpIdx];
    ExprId address = GetMemoryAddress(il, instr, memOpIdx, addr, thumb);

    uint32_t rt = RegisterToIndex(instr.operands[0].reg);
    uint32_t rt2 = RegisterToIndex(instr.operands[1].reg);

    if (isLoad) {
        /* LDRD Rt, Rt2, [Rn, #offset] - load two words */
        if (arch->GetEndianness() == LittleEndian) {
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, rt, il.Load(4, address)));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, rt2, il.Load(4, il.Add(4, address, il.Const(4, 4)))));
        } else {
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, rt2, il.Load(4, address)));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, rt, il.Load(4, il.Add(4, address, il.Const(4, 4)))));
        }
    } else {
        /* STRD Rt, Rt2, [Rn, #offset] - store two words */
        if (arch->GetEndianness() == LittleEndian) {
            ConditionExecute(il, instr.cond,
                il.Store(4, address, il.Register(4, rt)));
            ConditionExecute(il, instr.cond,
                il.Store(4, il.Add(4, address, il.Const(4, 4)), il.Register(4, rt2)));
        } else {
            ConditionExecute(il, instr.cond,
                il.Store(4, address, il.Register(4, rt2)));
            ConditionExecute(il, instr.cond,
                il.Store(4, il.Add(4, address, il.Const(4, 4)), il.Register(4, rt)));
        }
    }

    /* Handle writeback
     * Pre-indexed (!): MEM_PRE_IDX - write new base (base + offset)
     * Post-indexed: MEM_POST_IDX - write new base (base + offset)
     * Offset only: MEM_IMM - no writeback
     */
    bool hasWriteback = (memOp.cls == MEM_PRE_IDX || memOp.cls == MEM_POST_IDX);
    if (hasWriteback && memOp.reg != REG_PC) {
        /* Compute new base: base + offset */
        ExprId base = il.Register(4, RegisterToIndex(memOp.reg));
        ExprId offset;
        if (memOp.flags.offsetRegUsed && memOp.offset != REG_INVALID) {
            offset = il.Register(4, RegisterToIndex(memOp.offset));
            if (!memOp.flags.add) offset = il.Neg(4, offset);
        } else {
            int32_t imm = (int32_t)memOp.imm;
            if (!memOp.flags.add) imm = -imm;
            offset = il.Const(4, imm);
        }
        ExprId newBase = il.Add(4, base, offset);
        ConditionExecute(il, instr.cond,
            il.SetRegister(4, RegisterToIndex(memOp.reg), newBase));
    }

    return true;
}

/* Lift load/store multiple instructions */
bool LiftLoadStoreMultiple(Architecture* arch, LowLevelILFunction& il,
    Instruction& instr, uint64_t addr, bool thumb)
{
    (void)arch;
    (void)addr;
    (void)thumb;
    size_t addrSize = 4;

    /* Find register list and base register */
    uint32_t regList = 0;
    Register baseReg = REG_SP;
    bool writeback = false;

    int operandCount = GetOperandCount(instr);
    for (int i = 0; i < operandCount; i++) {
        if (instr.operands[i].cls == REG_LIST) {
            regList = instr.operands[i].imm;
        } else if (instr.operands[i].cls == REG) {
            baseReg = instr.operands[i].reg;
            writeback = instr.operands[i].flags.wb;
        }
    }

    if (instr.operation == ARMV5_PUSH || instr.operation == ARMV5_POP) {
        baseReg = REG_SP;
        writeback = true;
    }

    uint32_t numRegs = GetNumberOfRegs(regList);

    /* Use lambda ConditionExecute to wrap ALL instructions in one conditional block */
    switch (instr.operation) {
        case ARMV5_LDM:
        case ARMV5_LDMIA:
        case ARMV5_LDMIB:
        case ARMV5_LDMDA:
        case ARMV5_LDMDB:
        case ARMV5_POP:
            ConditionExecute(addrSize, instr.cond, instr, il,
                [&](size_t addrSize, Instruction& instr, LowLevelILFunction& il) {
                    (void)addrSize;

                    /* Cache base register in TEMP(0) in case it's in the reglist */
                    ExprId base = 0;
                    switch (instr.operation) {
                        case ARMV5_LDM:
                        case ARMV5_LDMIA:
                        case ARMV5_POP:
                            base = il.Register(4, RegisterToIndex(baseReg));
                            break;
                        case ARMV5_LDMIB:
                            base = il.Add(4, il.Register(4, RegisterToIndex(baseReg)), il.Const(1, 4));
                            break;
                        case ARMV5_LDMDB:
                            base = il.Sub(4, il.Register(4, RegisterToIndex(baseReg)), il.Const(1, 4 * numRegs));
                            break;
                        case ARMV5_LDMDA:
                            base = il.Sub(4, il.Register(4, RegisterToIndex(baseReg)), il.Const(1, 4 * numRegs - 4));
                            break;
                        default:
                            base = il.Register(4, RegisterToIndex(baseReg));
                            break;
                    }
                    il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), base));

                    /* Load each register - defer PC write to TEMP(1) */
                    for (int reg = 0, slot = 0; reg < 16; reg++) {
                        if (regList & (1 << reg)) {
                            il.AddInstruction(
                                il.SetRegister(4,
                                    /* Writes to PC are deferred to a final Jump */
                                    (reg != REG_PC) ? reg : LLIL_TEMP(1),
                                    il.Load(4,
                                        il.Add(4,
                                            il.Register(4, LLIL_TEMP(0)),
                                            il.Const(1, 4 * slot++)
                                        )
                                    )
                                )
                            );
                        }
                    }

                    /* Handle writeback */
                    if (writeback) {
                        ExprId wb = BN_INVALID_OPERAND;
                        switch (instr.operation) {
                            case ARMV5_LDM:
                            case ARMV5_LDMIA:
                            case ARMV5_POP:
                                wb = il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 4 * numRegs));
                                break;
                            case ARMV5_LDMIB:
                                wb = il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 4 * numRegs - 4));
                                break;
                            case ARMV5_LDMDB:
                                wb = il.Register(4, LLIL_TEMP(0));
                                break;
                            case ARMV5_LDMDA:
                                wb = il.Sub(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 4));
                                break;
                            default:
                                wb = il.Register(4, LLIL_TEMP(0));
                                break;
                        }
                        /* If base reg is in reglist, result is undefined */
                        if ((1 << baseReg) & regList) {
                            wb = il.Undefined();
                        }
                        il.AddInstruction(il.SetRegister(4, RegisterToIndex(baseReg), wb));
                    }

                    /* If PC was in the reglist, jump to it now */
                    if (regList & (1 << REG_PC)) {
                        il.AddInstruction(il.Jump(il.Register(4, LLIL_TEMP(1))));
                    }
                });
            break;

        case ARMV5_STM:
        case ARMV5_STMIA:
        case ARMV5_STMIB:
        case ARMV5_STMDA:
        case ARMV5_STMDB:
        case ARMV5_PUSH:
            ConditionExecute(addrSize, instr.cond, instr, il,
                [&](size_t addrSize, Instruction& instr, LowLevelILFunction& il) {
                    (void)addrSize;

                    /* Calculate starting address based on mode */
                    ExprId base = 0;
                    switch (instr.operation) {
                        case ARMV5_STM:
                        case ARMV5_STMIA:
                            base = il.Register(4, RegisterToIndex(baseReg));
                            break;
                        case ARMV5_STMIB:
                            base = il.Add(4, il.Register(4, RegisterToIndex(baseReg)), il.Const(1, 4));
                            break;
                        case ARMV5_STMDB:
                        case ARMV5_PUSH:
                            base = il.Sub(4, il.Register(4, RegisterToIndex(baseReg)), il.Const(1, 4 * numRegs));
                            break;
                        case ARMV5_STMDA:
                            base = il.Sub(4, il.Register(4, RegisterToIndex(baseReg)), il.Const(1, 4 * numRegs - 4));
                            break;
                        default:
                            base = il.Register(4, RegisterToIndex(baseReg));
                            break;
                    }
                    il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), base));

                    /* Store each register */
                    for (int reg = 0, slot = 0; reg < 16; reg++) {
                        if (regList & (1 << reg)) {
                            il.AddInstruction(
                                il.Store(4,
                                    il.Add(4,
                                        il.Register(4, LLIL_TEMP(0)),
                                        il.Const(1, 4 * slot++)
                                    ),
                                    il.Register(4, reg)
                                )
                            );
                        }
                    }

                    /* Handle writeback */
                    if (writeback) {
                        ExprId wb = BN_INVALID_OPERAND;
                        switch (instr.operation) {
                            case ARMV5_STM:
                            case ARMV5_STMIA:
                                wb = il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 4 * numRegs));
                                break;
                            case ARMV5_STMIB:
                                wb = il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 4 * numRegs - 4));
                                break;
                            case ARMV5_STMDB:
                            case ARMV5_PUSH:
                                wb = il.Register(4, LLIL_TEMP(0));
                                break;
                            case ARMV5_STMDA:
                                wb = il.Sub(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 4));
                                break;
                            default:
                                wb = il.Register(4, LLIL_TEMP(0));
                                break;
                        }
                        il.AddInstruction(il.SetRegister(4, RegisterToIndex(baseReg), wb));
                    }
                });
            break;

        default:
            return false;
    }

    return true;
}

/* Main ARM IL lifting function */
bool GetLowLevelILForArmInstruction(Architecture* arch, uint64_t addr,
    LowLevelILFunction& il, Instruction& instr, size_t addrSize)
{
    (void)arch;
    (void)addr;
    (void)addrSize;
    InstructionOperand& op1 = instr.operands[0];
    InstructionOperand& op2 = instr.operands[1];
    InstructionOperand& op3 = instr.operands[2];
    InstructionOperand& op4 = instr.operands[3];
    (void)op4; /* May be unused */
    LowLevelILLabel trueLabel, falseLabel, endLabel;
    /* Use GetFlagWriteType to get correct flag write type for each instruction */
    uint32_t flags = GetFlagWriteType(instr);
    LowLevelILLabel trueCode, falseCode;
    switch (instr.operation) {
        /*
         * =======================================================================
         * DATA PROCESSING INSTRUCTIONS
         * =======================================================================
         *
         * ARM data processing instruction format (bits [31:0]):
         *   [31:28] = Condition code (when to execute)
         *   [27:26] = 00 for data processing
         *   [25]    = I bit (1=immediate operand, 0=register operand)
         *   [24:21] = Opcode (ADD=0100, SUB=0010, etc.)
         *   [20]    = S bit (1=update flags NZCV, 0=don't update)
         *   [19:16] = Rn (first operand register)
         *   [15:12] = Rd (destination register)
         *   [11:0]  = Operand2 (flexible second operand)
         *
         * Pattern: Rd = Rn <op> Operand2
         * If S bit set, updates flags N (negative), Z (zero), C (carry), V (overflow)
         *
         * ConditionExecute wraps the IL in a conditional check based on NZCV flags.
         * SetRegisterOrBranch handles writing to Rd, treating PC writes as jumps.
         * 'flags' is set by GetFlagWriteType() based on the specific instruction.
         */

        case ARMV5_ADD:
            /*
             * ADD{S}{cond} Rd, Rn, Operand2
             * Rd = Rn + Operand2
             * Flags: N=sign, Z=zero, C=carry out, V=signed overflow
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.Add(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op2, addr),
                    ReadILOperand(il, op3, addr), flags)));
            break;

        case ARMV5_ADC:
            /*
             * ADC{S}{cond} Rd, Rn, Operand2
             * Rd = Rn + Operand2 + C (add with carry)
             * Used for multi-word addition: ADD low words, ADC high words.
             * The carry from ADD propagates via the C flag.
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.AddCarry(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op2, addr),
                    ReadILOperand(il, op3, addr), il.Flag(IL_FLAG_C), flags)));
            break;

        case ARMV5_SUB:
            /*
             * SUB{S}{cond} Rd, Rn, Operand2
             * Rd = Rn - Operand2
             * Flags: N=sign, Z=zero, C=NOT borrow (1 if no borrow), V=signed overflow
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.Sub(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op2, addr),
                    ReadILOperand(il, op3, addr), flags)));
            break;

        case ARMV5_SBC:
            /*
             * SBC{S}{cond} Rd, Rn, Operand2
             * Rd = Rn - Operand2 - NOT(C)  (subtract with carry/borrow)
             * ARM uses inverted carry for borrow: C=1 means no borrow, C=0 means borrow.
             * Binary Ninja's SubBorrow expects borrow flag, so we invert C with NOT.
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.SubBorrow(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op2, addr),
                    ReadILOperand(il, op3, addr), il.Not(1, il.Flag(IL_FLAG_C)), flags)));
            break;

        case ARMV5_RSB:
            /*
             * RSB{S}{cond} Rd, Rn, Operand2
             * Rd = Operand2 - Rn  (reverse subtract)
             * Same as SUB but operands swapped. Useful when Operand2 has the value
             * you want to subtract FROM (e.g., RSB Rd, Rn, #0 gives Rd = -Rn).
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.Sub(get_register_size(op1.reg),
                    ReadILOperand(il, op3, addr),
                    ReadRegisterOrPointer(il, op2, addr), flags)));
            break;

        case ARMV5_RSC:
            /*
             * RSC{S}{cond} Rd, Rn, Operand2
             * Rd = Operand2 - Rn - NOT(C)  (reverse subtract with carry)
             * Combines RSB semantics with carry propagation for multi-word subtraction.
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.SubBorrow(get_register_size(op1.reg),
                    ReadILOperand(il, op3, addr),
                    ReadRegisterOrPointer(il, op2, addr), il.Not(1, il.Flag(IL_FLAG_C)), flags)));
            break;

        case ARMV5_AND:
            /*
             * AND{S}{cond} Rd, Rn, Operand2
             * Rd = Rn AND Operand2  (bitwise AND)
             * Commonly used for masking bits or testing bit patterns.
             * Flags: N=bit 31, Z=result==0, C=carry from shifter (if applicable)
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.And(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op2, addr),
                    ReadILOperand(il, op3, addr), flags)));
            break;

        case ARMV5_EOR:
            /*
             * EOR{S}{cond} Rd, Rn, Operand2
             * Rd = Rn XOR Operand2  (bitwise exclusive OR)
             * Used for toggling bits or simple encryption/checksums.
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.Xor(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op2, addr),
                    ReadILOperand(il, op3, addr), flags)));
            break;

        case ARMV5_ORR:
            /*
             * ORR{S}{cond} Rd, Rn, Operand2
             * Rd = Rn OR Operand2  (bitwise inclusive OR)
             * Used for setting specific bits while preserving others.
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.Or(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op2, addr),
                    ReadILOperand(il, op3, addr), flags)));
            break;

        case ARMV5_BIC:
            /*
             * BIC{S}{cond} Rd, Rn, Operand2
             * Rd = Rn AND NOT(Operand2)  (bit clear)
             * Clears the bits in Rn that are set in Operand2.
             * Equivalent to: Rn & ~Operand2
             * Example: BIC R0, R0, #0x80 clears bit 7 of R0.
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.And(4,
                    ReadRegisterOrPointer(il, op2, addr),
                    il.Not(4, ReadILOperand(il, op3, addr)), flags)));
            break;

        case ARMV5_MOV:
            /*
             * MOV{S}{cond} Rd, Operand2
             * Rd = Operand2  (move/copy value)
             * Note: Only two operands - Rn is ignored (should be 0 in encoding).
             * If S bit set, flags are set based on the value moved (and shifter carry).
             *
             * For flag setting: wrap in AND 0xFFFFFFFF to provide an operation that
             * Binary Ninja can use to compute NZ flags (C comes from shifter).
             */
            {
                ExprId value = ReadILOperand(il, op2, addr);
                if (instr.setsFlags)
                    value = il.And(4, value, il.Const(4, 0xFFFFFFFF), flags);
                ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg, value));
            }
            break;

        case ARMV5_MVN:
            /*
             * MVN{S}{cond} Rd, Operand2
             * Rd = NOT(Operand2)  (move NOT / bitwise complement)
             * Inverts all bits. MVN R0, #0 gives R0 = 0xFFFFFFFF.
             *
             * The NOT operation itself can set NZ flags through the And wrapper.
             */
            {
                ExprId value = il.Not(4, ReadILOperand(il, op2, addr));
                if (instr.setsFlags)
                    value = il.And(4, value, il.Const(4, 0xFFFFFFFF), flags);
                ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg, value));
            }
            break;

        case ARMV5_CMP:
            /*
             * CMP{cond} Rn, Operand2
             * Flags = Rn - Operand2  (compare, update flags only)
             * Same as SUBS but result is discarded, only flags are updated.
             * Used before conditional branches/instructions.
             */
            ConditionExecute(il, instr.cond,
                il.Sub(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op1, addr),
                    ReadILOperand(il, op2, addr), flags));
            break;

        case ARMV5_CMN:
            /*
             * CMN{cond} Rn, Operand2
             * Flags = Rn + Operand2  (compare negative)
             * Like CMP but adds instead of subtracts.
             * CMN Rn, #x is equivalent to CMP Rn, #-x (but uses less encoding space).
             */
            ConditionExecute(il, instr.cond,
                il.Add(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op1, addr),
                    ReadILOperand(il, op2, addr), flags));
            break;

        case ARMV5_TST:
            /*
             * TST{cond} Rn, Operand2
             * Flags = Rn AND Operand2  (test bits)
             * Result discarded, only N and Z flags updated.
             * Common pattern: TST R0, #mask; BEQ/BNE to branch on bit state.
             */
            ConditionExecute(il, instr.cond,
                il.And(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op1, addr),
                    ReadILOperand(il, op2, addr), flags));
            break;

        case ARMV5_TEQ:
            /*
             * TEQ{cond} Rn, Operand2
             * Flags = Rn XOR Operand2  (test equivalence)
             * Result discarded. Z=1 if Rn equals Operand2.
             * Less common than TST but useful for equality checks.
             */
            ConditionExecute(il, instr.cond,
                il.Xor(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op1, addr),
                    ReadILOperand(il, op2, addr), flags));
            break;

        /*
         * =======================================================================
         * MULTIPLY INSTRUCTIONS
         * =======================================================================
         *
         * ARM multiply instructions produce 32-bit or 64-bit results.
         * Unlike data processing, multiply has distinct register operands:
         *
         * MUL/MLA format (32-bit result):
         *   [31:28] = Condition
         *   [27:21] = Opcode pattern
         *   [20]    = S bit (update N, Z flags only - not C, V)
         *   [19:16] = Rd (destination)
         *   [15:12] = Rn (accumulate register for MLA, SBZ for MUL)
         *   [11:8]  = Rs (multiplier)
         *   [3:0]   = Rm (multiplicand)
         *
         * Long multiply format (64-bit result):
         *   [19:16] = RdHi (high 32 bits of result)
         *   [15:12] = RdLo (low 32 bits of result)
         *
         * Note: Multiply only sets N and Z flags, never C or V (undefined behavior).
         */

        case ARMV5_MUL:
            /*
             * MUL{S}{cond} Rd, Rm, Rs
             * Rd = Rm * Rs  (low 32 bits of 32x32->64 multiply)
             * Operand layout: Rd, Rm, Rs (or Rd, Rm if 2-operand form)
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.Mult(get_register_size(op2.reg),
                    ReadRegisterOrPointer(il, op2, addr),
                    (op3.cls == NONE) ? ReadRegisterOrPointer(il, op1, addr) : ReadRegisterOrPointer(il, op3, addr),
                    instr.setsFlags ? IL_FLAGWRITE_NZ : IL_FLAGWRITE_NONE)));
            break;

        case ARMV5_MLA:
            /*
             * MLA{S}{cond} Rd, Rm, Rs, Rn
             * Rd = Rn + Rm * Rs  (multiply-accumulate)
             * Common in DSP code for running sums: Rd = sum + (sample * coeff)
             *
             * Binary Ninja expects accumulator first in il.Add (matches ARMv7 style).
             */
            ConditionExecute(il, instr.cond, SetRegisterOrBranch(il, op1.reg,
                il.Add(get_register_size(op1.reg),
                    ReadRegisterOrPointer(il, op4, addr),
                    il.Mult(get_register_size(op2.reg),
                        ReadRegisterOrPointer(il, op2, addr),
                        ReadRegisterOrPointer(il, op3, addr)),
                    instr.setsFlags ? IL_FLAGWRITE_NZ : IL_FLAGWRITE_NONE)));
            break;

        case ARMV5_UMULL:
        {
            /*
             * UMULL{S}{cond} RdLo, RdHi, Rm, Rs
             * {RdHi, RdLo} = Rm * Rs  (64-bit unsigned result)
             *
             * Used when full 64-bit result is needed (e.g., cryptography, big integers).
             * Binary Ninja's SetRegisterSplit writes a 64-bit value to two 32-bit regs.
             * Order: high reg first, low reg second.
             */
            ExprId product = il.MultDoublePrecUnsigned(4,
                ReadRegisterOrPointer(il, op3, addr),
                ReadRegisterOrPointer(il, op4, addr));
            ConditionExecute(il, instr.cond, il.SetRegisterSplit(4,
                RegisterToIndex(op2.reg), RegisterToIndex(op1.reg), product,
                instr.setsFlags ? IL_FLAGWRITE_NZ : IL_FLAGWRITE_NONE));
            break;
        }

        case ARMV5_UMLAL:
        {
            /*
             * UMLAL{S}{cond} RdLo, RdHi, Rm, Rs
             * {RdHi, RdLo} = {RdHi, RdLo} + Rm * Rs  (64-bit unsigned multiply-accumulate)
             *
             * Accumulates into the existing 64-bit value in {RdHi, RdLo}.
             * Used for multi-precision arithmetic (e.g., bignum multiplication).
             */
            ExprId product = il.MultDoublePrecUnsigned(4,
                ReadRegisterOrPointer(il, op3, addr),
                ReadRegisterOrPointer(il, op4, addr));
            ExprId acc = il.RegisterSplit(4, RegisterToIndex(op2.reg), RegisterToIndex(op1.reg));
            ConditionExecute(il, instr.cond, il.SetRegisterSplit(4,
                RegisterToIndex(op2.reg), RegisterToIndex(op1.reg), il.Add(8, product, acc),
                instr.setsFlags ? IL_FLAGWRITE_NZ : IL_FLAGWRITE_NONE));
            break;
        }

        case ARMV5_SMULL:
        {
            /*
             * SMULL{S}{cond} RdLo, RdHi, Rm, Rs
             * {RdHi, RdLo} = Rm * Rs  (64-bit signed result)
             *
             * Same as UMULL but treats operands as signed (2's complement).
             * Sign-extends the 32-bit operands before multiplication.
             */
            ExprId product = il.MultDoublePrecSigned(4,
                ReadRegisterOrPointer(il, op3, addr),
                ReadRegisterOrPointer(il, op4, addr));
            ConditionExecute(il, instr.cond, il.SetRegisterSplit(4,
                RegisterToIndex(op2.reg), RegisterToIndex(op1.reg), product,
                instr.setsFlags ? IL_FLAGWRITE_NZ : IL_FLAGWRITE_NONE));
            break;
        }

        case ARMV5_SMLAL:
        {
            /*
             * SMLAL{S}{cond} RdLo, RdHi, Rm, Rs
             * {RdHi, RdLo} = {RdHi, RdLo} + Rm * Rs  (64-bit signed multiply-accumulate)
             *
             * Signed version of UMLAL. The 64-bit accumulator is treated as signed.
             */
            ExprId product = il.MultDoublePrecSigned(4,
                ReadRegisterOrPointer(il, op3, addr),
                ReadRegisterOrPointer(il, op4, addr));
            ExprId acc = il.RegisterSplit(4, RegisterToIndex(op2.reg), RegisterToIndex(op1.reg));
            ConditionExecute(il, instr.cond, il.SetRegisterSplit(4,
                RegisterToIndex(op2.reg), RegisterToIndex(op1.reg), il.Add(8, product, acc),
                instr.setsFlags ? IL_FLAGWRITE_NZ : IL_FLAGWRITE_NONE));
            break;
        }

        /*
         * DSP MULTIPLY INSTRUCTIONS (ARMv5E extensions)
         *
         * These perform 16x16 -> 32 or 32x16 -> 32 signed multiplies.
         * B = Bottom halfword (bits [15:0])
         * T = Top halfword (bits [31:16])
         *
         * SMULxy: Rd = Rn[x] * Rm[y]  (16x16 -> 32 signed)
         * SMULWy: Rd = (Rn * Rm[y]) >> 16  (32x16 -> 32 signed, keep high 32 bits)
         * SMLAxy: Rd = Rn[x] * Rm[y] + Ra  (16x16 + 32 -> 32 signed)
         * SMLAWy: Rd = ((Rn * Rm[y]) >> 16) + Ra  (32x16 + 32 -> 32 signed)
         * SMLALxy: {RdHi,RdLo} += Rn[x] * Rm[y]  (16x16 + 64 -> 64 signed)
         */

        /* SMULxy - 16x16 -> 32 signed multiply */
        case ARMV5_SMULBB: {
            /* Rd = SignExtend(Rn[15:0]) * SignExtend(Rm[15:0]) */
            ExprId mul_op1 = il.SignExtend(4, il.LowPart(2, ILREG(1)));
            ExprId mul_op2 = il.SignExtend(4, il.LowPart(2, ILREG(2)));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.Mult(4, mul_op1, mul_op2)));
            break;
        }

        case ARMV5_SMULBT: {
            /* Rd = SignExtend(Rn[15:0]) * SignExtend(Rm[31:16]) */
            ExprId mul_op1 = il.SignExtend(4, il.LowPart(2, ILREG(1)));
            ExprId mul_op2 = il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(2), il.Const(1, 16))));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.Mult(4, mul_op1, mul_op2)));
            break;
        }

        case ARMV5_SMULTB: {
            /* Rd = SignExtend(Rn[31:16]) * SignExtend(Rm[15:0]) */
            ExprId mul_op1 = il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(1), il.Const(1, 16))));
            ExprId mul_op2 = il.SignExtend(4, il.LowPart(2, ILREG(2)));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.Mult(4, mul_op1, mul_op2)));
            break;
        }

        case ARMV5_SMULTT: {
            /* Rd = SignExtend(Rn[31:16]) * SignExtend(Rm[31:16]) */
            ExprId mul_op1 = il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(1), il.Const(1, 16))));
            ExprId mul_op2 = il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(2), il.Const(1, 16))));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.Mult(4, mul_op1, mul_op2)));
            break;
        }

        /* SMULWy - 32x16 -> 32 signed multiply (high 32 bits of 48-bit result) */
        case ARMV5_SMULWB: {
            /* Rd = (Rn * SignExtend(Rm[15:0])) >> 16 */
            ExprId mul_op1 = il.SignExtend(8, ILREG(1));
            ExprId mul_op2 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, ILREG(2))));
            ExprId product = il.Mult(8, mul_op1, mul_op2);
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.LowPart(4, il.ArithShiftRight(8, product, il.Const(1, 16)))));
            break;
        }

        case ARMV5_SMULWT: {
            /* Rd = (Rn * SignExtend(Rm[31:16])) >> 16 */
            ExprId mul_op1 = il.SignExtend(8, ILREG(1));
            ExprId mul_op2 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(2), il.Const(1, 16)))));
            ExprId product = il.Mult(8, mul_op1, mul_op2);
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.LowPart(4, il.ArithShiftRight(8, product, il.Const(1, 16)))));
            break;
        }

        /* SMLAxy - 16x16 + 32 -> 32 signed multiply-accumulate */
        case ARMV5_SMLABB: {
            /* Rd = SignExtend(Rn[15:0]) * SignExtend(Rm[15:0]) + Ra */
            ExprId mul_op1 = il.SignExtend(4, il.LowPart(2, ILREG(1)));
            ExprId mul_op2 = il.SignExtend(4, il.LowPart(2, ILREG(2)));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.Add(4, il.Mult(4, mul_op1, mul_op2), ILREG(3))));
            break;
        }

        case ARMV5_SMLABT: {
            /* Rd = SignExtend(Rn[15:0]) * SignExtend(Rm[31:16]) + Ra */
            ExprId mul_op1 = il.SignExtend(4, il.LowPart(2, ILREG(1)));
            ExprId mul_op2 = il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(2), il.Const(1, 16))));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.Add(4, il.Mult(4, mul_op1, mul_op2), ILREG(3))));
            break;
        }

        case ARMV5_SMLATB: {
            /* Rd = SignExtend(Rn[31:16]) * SignExtend(Rm[15:0]) + Ra */
            ExprId mul_op1 = il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(1), il.Const(1, 16))));
            ExprId mul_op2 = il.SignExtend(4, il.LowPart(2, ILREG(2)));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.Add(4, il.Mult(4, mul_op1, mul_op2), ILREG(3))));
            break;
        }

        case ARMV5_SMLATT: {
            /* Rd = SignExtend(Rn[31:16]) * SignExtend(Rm[31:16]) + Ra */
            ExprId mul_op1 = il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(1), il.Const(1, 16))));
            ExprId mul_op2 = il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(2), il.Const(1, 16))));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.Add(4, il.Mult(4, mul_op1, mul_op2), ILREG(3))));
            break;
        }

        /* SMLAWy - 32x16 + 32 -> 32 signed multiply-accumulate */
        case ARMV5_SMLAWB: {
            /* Rd = ((Rn * SignExtend(Rm[15:0])) >> 16) + Ra */
            ExprId mul_op1 = il.SignExtend(8, ILREG(1));
            ExprId mul_op2 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, ILREG(2))));
            ExprId product = il.LowPart(4, il.ArithShiftRight(8, il.Mult(8, mul_op1, mul_op2), il.Const(1, 16)));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.Add(4, product, ILREG(3))));
            break;
        }

        case ARMV5_SMLAWT: {
            /* Rd = ((Rn * SignExtend(Rm[31:16])) >> 16) + Ra */
            ExprId mul_op1 = il.SignExtend(8, ILREG(1));
            ExprId mul_op2 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(2), il.Const(1, 16)))));
            ExprId product = il.LowPart(4, il.ArithShiftRight(8, il.Mult(8, mul_op1, mul_op2), il.Const(1, 16)));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    il.Add(4, product, ILREG(3))));
            break;
        }

        /* SMLALxy - 16x16 + 64 -> 64 signed multiply-accumulate */
        case ARMV5_SMLALBB: {
            /* {RdHi,RdLo} = {RdHi,RdLo} + SignExtend(Rn[15:0]) * SignExtend(Rm[15:0]) */
            ExprId mul_op1 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, ILREG(2))));
            ExprId mul_op2 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, ILREG(3))));
            ExprId product = il.Mult(8, mul_op1, mul_op2);
            ExprId acc = il.RegisterSplit(4,
                RegisterToIndex(instr.operands[1].reg),
                RegisterToIndex(instr.operands[0].reg));
            ConditionExecute(il, instr.cond, il.SetRegisterSplit(4,
                RegisterToIndex(instr.operands[1].reg),
                RegisterToIndex(instr.operands[0].reg),
                il.Add(8, acc, product)));
            break;
        }

        case ARMV5_SMLALBT: {
            /* {RdHi,RdLo} = {RdHi,RdLo} + SignExtend(Rn[15:0]) * SignExtend(Rm[31:16]) */
            ExprId mul_op1 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, ILREG(2))));
            ExprId mul_op2 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(3), il.Const(1, 16)))));
            ExprId product = il.Mult(8, mul_op1, mul_op2);
            ExprId acc = il.RegisterSplit(4,
                RegisterToIndex(instr.operands[1].reg),
                RegisterToIndex(instr.operands[0].reg));
            ConditionExecute(il, instr.cond, il.SetRegisterSplit(4,
                RegisterToIndex(instr.operands[1].reg),
                RegisterToIndex(instr.operands[0].reg),
                il.Add(8, acc, product)));
            break;
        }

        case ARMV5_SMLALTB: {
            /* {RdHi,RdLo} = {RdHi,RdLo} + SignExtend(Rn[31:16]) * SignExtend(Rm[15:0]) */
            ExprId mul_op1 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(2), il.Const(1, 16)))));
            ExprId mul_op2 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, ILREG(3))));
            ExprId product = il.Mult(8, mul_op1, mul_op2);
            ExprId acc = il.RegisterSplit(4,
                RegisterToIndex(instr.operands[1].reg),
                RegisterToIndex(instr.operands[0].reg));
            ConditionExecute(il, instr.cond, il.SetRegisterSplit(4,
                RegisterToIndex(instr.operands[1].reg),
                RegisterToIndex(instr.operands[0].reg),
                il.Add(8, acc, product)));
            break;
        }

        case ARMV5_SMLALTT: {
            /* {RdHi,RdLo} = {RdHi,RdLo} + SignExtend(Rn[31:16]) * SignExtend(Rm[31:16]) */
            ExprId mul_op1 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(2), il.Const(1, 16)))));
            ExprId mul_op2 = il.SignExtend(8, il.SignExtend(4, il.LowPart(2, il.ArithShiftRight(4, ILREG(3), il.Const(1, 16)))));
            ExprId product = il.Mult(8, mul_op1, mul_op2);
            ExprId acc = il.RegisterSplit(4,
                RegisterToIndex(instr.operands[1].reg),
                RegisterToIndex(instr.operands[0].reg));
            ConditionExecute(il, instr.cond, il.SetRegisterSplit(4,
                RegisterToIndex(instr.operands[1].reg),
                RegisterToIndex(instr.operands[0].reg),
                il.Add(8, acc, product)));
            break;
        }

        /*
         * =======================================================================
         * BRANCH INSTRUCTIONS
         * =======================================================================
         *
         * Branch instruction format (bits [31:0]):
         *   [31:28] = Condition code
         *   [27:25] = 101 for branch
         *   [24]    = L bit (1=BL link, 0=B branch)
         *   [23:0]  = Signed 24-bit offset (shifted left by 2 = 26-bit range)
         *
         * Branch target = PC + 8 + (sign_extend(offset) << 2)
         * The disassembler pre-computes the absolute target address.
         *
         * BX/BLX use register operand for interworking (ARM/Thumb switch).
         * Bit 0 of target address determines mode: 0=ARM, 1=Thumb.
         */

        case ARMV5_B:
            /*
             * B{cond} label
             * PC = target  (conditional branch)
             *
             * ConditionalJump handles:
             *   - Unconditional: direct jump
             *   - Conditional: If(cond) goto target; else goto fallthrough;
             *
             * Returns false to indicate no fall-through (this is a control flow terminator).
             */
            ConditionalJump(arch, il, instr.cond, addrSize, op1.imm, addr + 4);
            return false;

        case ARMV5_BL:
            /*
             * BL{cond} label
             * LR = return_address; PC = target  (branch with link / call)
             *
             * Sets LR to address of next instruction before branching.
             * This is the standard function call mechanism.
             * Binary Ninja's il.Call handles LR update implicitly.
             */
            ConditionExecute(il, instr.cond, il.Call(il.ConstPointer(4, op1.imm)));
            break;

        case ARMV5_BX:
            /*
             * BX{cond} Rm
             * PC = Rm  (branch and exchange - ARM/Thumb interworking)
             *
             * Bit 0 of Rm determines instruction set:
             *   Rm[0] = 0: Continue in ARM mode
             *   Rm[0] = 1: Switch to Thumb mode
             *
             * If Rm is LR, this is a function return. Binary Ninja prefers
             * il.Return for better decompilation.
             *
             * For other registers, use TailCall since BX to a non-LR register
             * is typically a tail call pattern (LDR Rx, =func; BX Rx).
             * This helps the decompiler recognize function boundaries.
             */
            if (op1.reg == REG_LR)
                ConditionExecute(il, instr.cond, il.Return(ReadILOperand(il, op1, addr, true)));
            else
                ConditionExecute(il, instr.cond, il.TailCall(ReadILOperand(il, op1, addr, true)));
            break;

        case ARMV5_BLX:
            /*
             * BLX{cond} Rm  or  BLX label
             * LR = return_address; PC = target  (branch, link, and exchange)
             *
             * Like BL but also handles interworking:
             *   - BLX Rm: Target mode from Rm[0]
             *   - BLX label: Always switches to other mode (ARM->Thumb or Thumb->ARM)
             *
             * ReadILOperand with isPointer=true handles both register and label operands.
             */
            ConditionExecute(il, instr.cond, il.Call(ReadILOperand(il, op1, addr, true)));
            break;

        /*
         * =======================================================================
         * LOAD/STORE INSTRUCTIONS
         * =======================================================================
         *
         * Load/Store instruction format varies by type:
         *
         * Word/Byte (LDR/STR/LDRB/STRB):
         *   [31:28] = Condition
         *   [27:26] = 01
         *   [25]    = I bit (0=immediate offset, 1=register offset)
         *   [24]    = P bit (1=pre-indexed, 0=post-indexed)
         *   [23]    = U bit (1=add offset, 0=subtract offset)
         *   [22]    = B bit (1=byte, 0=word)
         *   [21]    = W bit (1=write-back, 0=no write-back)
         *   [20]    = L bit (1=load, 0=store)
         *   [19:16] = Rn (base register)
         *   [15:12] = Rd (destination/source register)
         *   [11:0]  = Offset (immediate or register)
         *
         * Halfword/Signed (LDRH/STRH/LDRSB/LDRSH):
         *   Different encoding, uses bits [11:8] and [3:0] for 8-bit immediate.
         *
         * Addressing modes:
         *   - Offset: address = Rn + offset (no write-back)
         *   - Pre-indexed: address = Rn + offset, Rn = address
         *   - Post-indexed: address = Rn, Rn = Rn + offset
         */
        case ARMV5_LDR:
        case ARMV5_LDRB:
        case ARMV5_LDRH:
        case ARMV5_LDRSB:
        case ARMV5_LDRSH:
        case ARMV5_STR:
        case ARMV5_STRB:
        case ARMV5_STRH:
            return LiftLoadStore(arch, il, instr, addr, false);

        /* Load/Store doubleword */
        case ARMV5_LDRD:
        case ARMV5_STRD:
            return LiftLoadStoreDouble(arch, il, instr, addr, false);

        /* Load/Store multiple */
        case ARMV5_LDM:
        case ARMV5_LDMIA:
        case ARMV5_LDMIB:
        case ARMV5_LDMDA:
        case ARMV5_LDMDB:
        case ARMV5_STM:
        case ARMV5_STMIA:
        case ARMV5_STMIB:
        case ARMV5_STMDA:
        case ARMV5_STMDB:
        case ARMV5_PUSH:
        case ARMV5_POP:
            return LiftLoadStoreMultiple(arch, il, instr, addr, false);

        /* CLZ - Count Leading Zeros
         * Lifted as a loop like the official ARM architecture:
         *   temp0 = 0 (counter)
         *   temp1 = Rm (input)
         * loop:
         *   if (temp1 != 0) then { temp1 >>= 1; temp0++; goto loop; }
         *   Rd = 32 - temp0
         */
        case ARMV5_CLZ:
        {
            uint32_t rd = RegisterToIndex(instr.operands[0].reg);
            uint32_t rm = RegisterToIndex(instr.operands[1].reg);

            ConditionExecute(4, instr.cond, instr, il,
                [rd, rm](size_t addrSize, Instruction& instr, LowLevelILFunction& il) {
                    LowLevelILLabel loopStart, loopBody, loopDone;

                    // temp0 = 0 (bit counter)
                    il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Const(4, 0)));
                    // temp1 = Rm (working copy)
                    il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1), il.Register(4, rm)));

                    // Loop start
                    il.MarkLabel(loopStart);
                    // if (temp1 != 0) goto loopBody else loopDone
                    il.AddInstruction(il.If(
                        il.CompareNotEqual(4, il.Register(4, LLIL_TEMP(1)), il.Const(4, 0)),
                        loopBody, loopDone));

                    // Loop body: shift right and increment counter
                    il.MarkLabel(loopBody);
                    il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
                        il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(4, 1))));
                    il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
                        il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 1))));
                    il.AddInstruction(il.Goto(loopStart));

                    // Loop done: Rd = 32 - temp0
                    il.MarkLabel(loopDone);
                    il.AddInstruction(il.SetRegister(4, rd,
                        il.Sub(4, il.Const(4, 32), il.Register(4, LLIL_TEMP(0)))));
                });
            return true;
        }

        /* Software interrupt */
        case ARMV5_SWI:
        case ARMV5_SVC:
            ConditionExecute(il, instr.cond,
                il.SystemCall());
            return true;

        /* Breakpoint */
        case ARMV5_BKPT:
            il.AddInstruction(il.Breakpoint());
            return true;

        /* NOP */
        case ARMV5_NOP:
            il.AddInstruction(il.Nop());
            return true;

        /* DSP saturating arithmetic - lifted as native LLIL with saturation logic
         *
         * QADD:   Rd = saturate(Rm + Rn)
         * QSUB:   Rd = saturate(Rm - Rn)
         * QDADD:  Rd = saturate(Rm + saturate(Rn * 2))
         * QDSUB:  Rd = saturate(Rm - saturate(Rn * 2))
         *
         * Signed 32-bit saturation clamps to [0x80000000, 0x7FFFFFFF].
         * We use 64-bit arithmetic to detect overflow, then clamp.
         */
        case ARMV5_QADD:
        case ARMV5_QSUB:
        case ARMV5_QDADD:
        case ARMV5_QDSUB:
        {
            uint32_t rd = RegisterToIndex(instr.operands[0].reg);
            uint32_t rm = RegisterToIndex(instr.operands[1].reg);
            uint32_t rn = RegisterToIndex(instr.operands[2].reg);
            bool isAdd = (instr.operation == ARMV5_QADD || instr.operation == ARMV5_QDADD);
            bool isDouble = (instr.operation == ARMV5_QDADD || instr.operation == ARMV5_QDSUB);

            ConditionExecute(4, instr.cond, instr, il,
                [rd, rm, rn, isAdd, isDouble](size_t addrSize, Instruction& instr, LowLevelILFunction& il) {
                    LowLevelILLabel checkNegOvf, setNegOvf, noOverflow, done;

                    // temp0 = sign_extend_64(Rm)
                    il.AddInstruction(il.SetRegister(8, LLIL_TEMP(0),
                        il.SignExtend(8, il.Register(4, rm))));

                    // temp1 = sign_extend_64(Rn) or sign_extend_64(Rn * 2) with saturation
                    if (isDouble) {
                        // For QDADD/QDSUB: compute Rn * 2 in 64-bit, then saturate to 32-bit range
                        LowLevelILLabel dblCheckNeg, dblSetNeg, dblNoOvf, dblDone;

                        il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1),
                            il.Mult(8, il.SignExtend(8, il.Register(4, rn)), il.Const(8, 2))));

                        // Check positive overflow: temp1 > 0x7FFFFFFF
                        il.AddInstruction(il.If(
                            il.CompareSignedGreaterThan(8, il.Register(8, LLIL_TEMP(1)), il.Const(8, 0x7FFFFFFF)),
                            dblCheckNeg, dblNoOvf));

                        // Not positive overflow, check negative
                        il.MarkLabel(dblCheckNeg);
                        il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1), il.Const(8, 0x7FFFFFFF)));
                        il.AddInstruction(il.Goto(dblDone));

                        il.MarkLabel(dblNoOvf);
                        il.AddInstruction(il.If(
                            il.CompareSignedLessThan(8, il.Register(8, LLIL_TEMP(1)), il.Const(8, (int64_t)(int32_t)0x80000000)),
                            dblSetNeg, dblDone));

                        il.MarkLabel(dblSetNeg);
                        il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1), il.Const(8, (int64_t)(int32_t)0x80000000)));

                        il.MarkLabel(dblDone);
                    } else {
                        il.AddInstruction(il.SetRegister(8, LLIL_TEMP(1),
                            il.SignExtend(8, il.Register(4, rn))));
                    }

                    // temp2 = temp0 +/- temp1 (64-bit result)
                    if (isAdd) {
                        il.AddInstruction(il.SetRegister(8, LLIL_TEMP(2),
                            il.Add(8, il.Register(8, LLIL_TEMP(0)), il.Register(8, LLIL_TEMP(1)))));
                    } else {
                        il.AddInstruction(il.SetRegister(8, LLIL_TEMP(2),
                            il.Sub(8, il.Register(8, LLIL_TEMP(0)), il.Register(8, LLIL_TEMP(1)))));
                    }

                    // Saturate final result
                    // Check positive overflow: temp2 > 0x7FFFFFFF
                    il.AddInstruction(il.If(
                        il.CompareSignedGreaterThan(8, il.Register(8, LLIL_TEMP(2)), il.Const(8, 0x7FFFFFFF)),
                        checkNegOvf, noOverflow));

                    // Positive overflow path - but we jumped wrong way, fix labels
                    il.MarkLabel(checkNegOvf);
                    il.AddInstruction(il.SetRegister(4, rd, il.Const(4, 0x7FFFFFFF)));
                    il.AddInstruction(il.Goto(done));

                    // Check negative overflow
                    il.MarkLabel(noOverflow);
                    il.AddInstruction(il.If(
                        il.CompareSignedLessThan(8, il.Register(8, LLIL_TEMP(2)), il.Const(8, (int64_t)(int32_t)0x80000000)),
                        setNegOvf, done));

                    il.MarkLabel(setNegOvf);
                    il.AddInstruction(il.SetRegister(4, rd, il.Const(4, 0x80000000)));
                    il.AddInstruction(il.Goto(done));

                    // No overflow: Rd = low32(temp2)
                    il.MarkLabel(done);
                    il.AddInstruction(il.SetRegister(4, rd,
                        il.LowPart(4, il.Register(8, LLIL_TEMP(2)))));
                });

            return true;
        }

        /* MRS - read status register (CPSR/SPSR) into general register */
        case ARMV5_MRS:
            /*
             * MRS Rd, CPSR  or  MRS Rd, SPSR
             * Rd = status_register
             * Use intrinsic so decompiler shows _get_CPSR() etc.
             */
            ConditionExecute(il, instr.cond,
                il.Intrinsic(
                    { RegisterOrFlag::Register(RegisterToIndex(instr.operands[0].reg)) },
                    ARMV5_INTRIN_MRS,
                    { il.Const(1, instr.operands[1].reg) }  /* CPSR=0, SPSR=1 */
                ));
            return true;

        /* MSR - write to status register (CPSR/SPSR) */
        case ARMV5_MSR:
            /*
             * MSR CPSR_<fields>, Rm  or  MSR CPSR_<fields>, #imm
             * status_register = value (masked by fields)
             * Use intrinsic so decompiler shows _set_CPSR() etc.
             */
            ConditionExecute(il, instr.cond,
                il.Intrinsic(
                    {},
                    ARMV5_INTRIN_MSR,
                    { il.Const(1, instr.operands[0].reg),  /* destination PSR + mask */
                      ReadOperand(il, instr, 1, addr) }    /* value */
                ));
            return true;

        /* MRC - read from coprocessor to ARM register */
        case ARMV5_MRC:
            /*
             * MRC p<cp>, <op1>, Rd, CRn, CRm, <op2>
             * Operand layout from disassembler:
             *   [0] = coproc (REG_COPROCP, value in .reg)
             *   [1] = opc1 (COPROC_OPC, value in .imm)
             *   [2] = Rd (REG, destination register)
             *   [3] = CRn (REG_COPROCC, value in .reg)
             *   [4] = CRm (REG_COPROCC, value in .reg)
             *   [5] = opc2 (COPROC_OPC, value in .imm)
             * Generates: __mrc(15, 0, c1, c0, 0) like IDA
             *
             * Special case: When Rd=PC (r15), top 4 bits are written to NZCV flags
             * instead of the register. Used for CP15 test-and-clean operations.
             */
            {
                auto params = {
                    il.Const(1, instr.operands[0].reg),  /* coproc number (p15 = 15) */
                    il.Const(1, instr.operands[1].imm),  /* opc1 */
                    il.Const(1, instr.operands[3].reg),  /* CRn (c1 = 1) */
                    il.Const(1, instr.operands[4].reg),  /* CRm (c0 = 0) */
                    il.Const(1, instr.operands[5].imm),  /* opc2 */
                };

                if (instr.operands[2].reg == REG_PC) {
                    /* MRC with Rd=PC: write top 4 bits to NZCV flags */
                    ConditionExecute(il, instr.cond,
                        il.Intrinsic(
                            { RegisterOrFlag::Register(LLIL_TEMP(0)) },
                            ARMV5_INTRIN_COPROC_GETONEWORD,
                            params
                        ));
                    /* Extract bits 31, 30, 29, 28 to n, z, c, v flags */
                    ExprId temp = il.Register(4, LLIL_TEMP(0));
                    il.AddInstruction(il.SetFlag(IL_FLAG_N, il.And(4, il.LogicalShiftRight(4, temp, il.Const(4, 31)), il.Const(4, 1))));
                    il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.And(4, il.LogicalShiftRight(4, temp, il.Const(4, 30)), il.Const(4, 1))));
                    il.AddInstruction(il.SetFlag(IL_FLAG_C, il.And(4, il.LogicalShiftRight(4, temp, il.Const(4, 29)), il.Const(4, 1))));
                    il.AddInstruction(il.SetFlag(IL_FLAG_V, il.And(4, il.LogicalShiftRight(4, temp, il.Const(4, 28)), il.Const(4, 1))));
                } else {
                    ConditionExecute(il, instr.cond,
                        il.Intrinsic(
                            { RegisterOrFlag::Register(RegisterToIndex(instr.operands[2].reg)) },
                            ARMV5_INTRIN_COPROC_GETONEWORD,
                            params
                        ));
                }
            }
            return true;

        /* MCR - write ARM register to coprocessor */
        case ARMV5_MCR:
            /*
             * MCR p<cp>, <op1>, Rd, CRn, CRm, <op2>
             * Generates: __mcr(15, 0, value, c1, c0, 0) like IDA
             */
            {
                auto params = {
                    il.Const(1, instr.operands[0].reg),  /* coproc number */
                    il.Const(1, instr.operands[1].imm),  /* opc1 */
                    ILREG(2),                             /* Rd value */
                    il.Const(1, instr.operands[3].reg),  /* CRn */
                    il.Const(1, instr.operands[4].reg),  /* CRm */
                    il.Const(1, instr.operands[5].imm),  /* opc2 */
                };
                ConditionExecute(il, instr.cond,
                    il.Intrinsic({}, ARMV5_INTRIN_COPROC_SENDONEWORD, params));
            }
            return true;

        /* CDP - coprocessor data processing (no ARM register transfer) */
        case ARMV5_CDP:
            ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV5_INTRIN_CDP, {}));
            return true;

        /* LDC/STC - coprocessor load/store */
        case ARMV5_LDC:
            ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV5_INTRIN_LDC, {}));
            return true;
        case ARMV5_STC:
            ConditionExecute(il, instr.cond, il.Intrinsic({}, ARMV5_INTRIN_STC, {}));
            return true;

        /* MCRR/MRRC - two-word coprocessor transfers */
        case ARMV5_MCRR:
            ConditionExecute(il, instr.cond,
                il.Intrinsic({}, ARMV5_INTRIN_COPROC_SENDTWOWORDS, {}));
            return true;
        case ARMV5_MRRC:
            ConditionExecute(il, instr.cond,
                il.Intrinsic({}, ARMV5_INTRIN_COPROC_GETTWOWORDS, {}));
            return true;

        /* Swap - deprecated but supported */
        case ARMV5_SWP:
        case ARMV5_SWPB: {
            size_t size = (instr.operation == ARMV5_SWPB) ? 1 : 4;
            ExprId address = GetMemoryAddress(il, instr, 2, addr, false);
            ExprId temp = il.Load(size, address);
            ConditionExecute(il, instr.cond, il.Store(size, address,
                size == 1 ? il.LowPart(1, ILREG(1)) : ILREG(1)));
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, RegisterToIndex(instr.operands[0].reg),
                    size == 1 ? il.ZeroExtend(4, temp) : temp));
            return true;
        }

        /* PLD - preload data hint, no IL effect */
        case ARMV5_PLD:
            il.AddInstruction(il.Nop());
            return true;

        /* ===================================================================
         * VFP Instructions
         * ===================================================================
         */

        case ARMV5_VLDR: {
            /* VLDR{cond} Sd/Dd, [Rn, #imm]
             * Load single or double from memory to VFP register */
            Register destReg = op1.reg;
            size_t regSize = get_register_size(destReg);
            ExprId address = GetMemoryAddress(il, instr, 1, addr, false);
            ConditionExecute(il, instr.cond,
                il.SetRegister(regSize, RegisterToIndex(destReg),
                    il.Load(regSize, address)));
            return true;
        }

        case ARMV5_VSTR: {
            /* VSTR{cond} Sd/Dd, [Rn, #imm]
             * Store single or double from VFP register to memory */
            Register srcReg = op1.reg;
            size_t regSize = get_register_size(srcReg);
            ExprId address = GetMemoryAddress(il, instr, 1, addr, false);
            ConditionExecute(il, instr.cond,
                il.Store(regSize, address,
                    il.Register(regSize, RegisterToIndex(srcReg))));
            return true;
        }

        case ARMV5_VLDM: {
            /* VLDM{cond} Rn{!}, {Sd-Sn} or {Dd-Dn}
             * Load multiple VFP registers from memory */
            Register baseReg = op1.reg;
            bool writeback = op1.flags.wb;
            /* op2 has the first VFP register, operandCount tells us how many */
            int regCount = GetOperandCount(instr) - 1;
            if (regCount <= 0) regCount = 1;

            /* Determine register size from first VFP register */
            Register firstVfpReg = op2.reg;
            size_t regSize = get_register_size(firstVfpReg);

            for (int i = 0; i < regCount && instr.operands[i+1].cls == REG; i++) {
                Register vfpReg = instr.operands[i+1].reg;
                ExprId loadAddr = il.Add(4,
                    il.Register(4, RegisterToIndex(baseReg)),
                    il.Const(4, i * regSize));
                ConditionExecute(il, instr.cond,
                    il.SetRegister(regSize, RegisterToIndex(vfpReg),
                        il.Load(regSize, loadAddr)));
            }

            if (writeback) {
                ConditionExecute(il, instr.cond,
                    il.SetRegister(4, RegisterToIndex(baseReg),
                        il.Add(4, il.Register(4, RegisterToIndex(baseReg)),
                            il.Const(4, regCount * regSize))));
            }
            return true;
        }

        case ARMV5_VSTM: {
            /* VSTM{cond} Rn{!}, {Sd-Sn} or {Dd-Dn}
             * Store multiple VFP registers to memory */
            Register baseReg = op1.reg;
            bool writeback = op1.flags.wb;
            int regCount = GetOperandCount(instr) - 1;
            if (regCount <= 0) regCount = 1;

            Register firstVfpReg = op2.reg;
            size_t regSize = get_register_size(firstVfpReg);

            for (int i = 0; i < regCount && instr.operands[i+1].cls == REG; i++) {
                Register vfpReg = instr.operands[i+1].reg;
                ExprId storeAddr = il.Add(4,
                    il.Register(4, RegisterToIndex(baseReg)),
                    il.Const(4, i * regSize));
                ConditionExecute(il, instr.cond,
                    il.Store(regSize, storeAddr,
                        il.Register(regSize, RegisterToIndex(vfpReg))));
            }

            if (writeback) {
                ConditionExecute(il, instr.cond,
                    il.SetRegister(4, RegisterToIndex(baseReg),
                        il.Add(4, il.Register(4, RegisterToIndex(baseReg)),
                            il.Const(4, regCount * regSize))));
            }
            return true;
        }

        case ARMV5_VPUSH: {
            /* VPUSH{cond} {Sd-Sn} or {Dd-Dn}
             * Push VFP registers onto stack (decrement SP before) */
            int regCount = GetOperandCount(instr);
            if (regCount <= 0) regCount = 1;

            Register firstVfpReg = op1.reg;
            size_t regSize = get_register_size(firstVfpReg);

            /* Decrement SP first by total size */
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, REG_SP,
                    il.Sub(4, il.Register(4, REG_SP),
                        il.Const(4, regCount * regSize))));

            /* Store registers */
            for (int i = 0; i < regCount && instr.operands[i].cls == REG; i++) {
                Register vfpReg = instr.operands[i].reg;
                ExprId storeAddr = il.Add(4,
                    il.Register(4, REG_SP),
                    il.Const(4, i * regSize));
                ConditionExecute(il, instr.cond,
                    il.Store(regSize, storeAddr,
                        il.Register(regSize, RegisterToIndex(vfpReg))));
            }
            return true;
        }

        case ARMV5_VPOP: {
            /* VPOP{cond} {Sd-Sn} or {Dd-Dn}
             * Pop VFP registers from stack (increment SP after) */
            int regCount = GetOperandCount(instr);
            if (regCount <= 0) regCount = 1;

            Register firstVfpReg = op1.reg;
            size_t regSize = get_register_size(firstVfpReg);

            /* Load registers */
            for (int i = 0; i < regCount && instr.operands[i].cls == REG; i++) {
                Register vfpReg = instr.operands[i].reg;
                ExprId loadAddr = il.Add(4,
                    il.Register(4, REG_SP),
                    il.Const(4, i * regSize));
                ConditionExecute(il, instr.cond,
                    il.SetRegister(regSize, RegisterToIndex(vfpReg),
                        il.Load(regSize, loadAddr)));
            }

            /* Increment SP after */
            ConditionExecute(il, instr.cond,
                il.SetRegister(4, REG_SP,
                    il.Add(4, il.Register(4, REG_SP),
                        il.Const(4, regCount * regSize))));
            return true;
        }

        case ARMV5_VMOV: {
            /* VMOV can have multiple forms:
             * - VMOV Sd, Sm (single to single)
             * - VMOV Dd, Dm (double to double)
             * - VMOV Rd, Sn (VFP to ARM)
             * - VMOV Sn, Rd (ARM to VFP)
             * - VMOV Rd, Rn, Dm (double to two ARMs)
             * - VMOV Dm, Rd, Rn (two ARMs to double)
             */
            Register destReg = op1.reg;
            Register srcReg = op2.reg;
            size_t destSize = get_register_size(destReg);
            size_t srcSize = get_register_size(srcReg);

            if (destSize == srcSize) {
                /* Simple move */
                ConditionExecute(il, instr.cond,
                    il.SetRegister(destSize, RegisterToIndex(destReg),
                        il.Register(srcSize, RegisterToIndex(srcReg))));
            } else if (destSize == 8 && srcSize == 4 && op3.cls == REG) {
                /* VMOV Dm, Rd, Rn - two ARM regs to double */
                ExprId lowPart = il.Register(4, RegisterToIndex(srcReg));
                ExprId highPart = il.ShiftLeft(8,
                    il.ZeroExtend(8, il.Register(4, RegisterToIndex(op3.reg))),
                    il.Const(1, 32));
                ConditionExecute(il, instr.cond,
                    il.SetRegister(8, RegisterToIndex(destReg),
                        il.Or(8, il.ZeroExtend(8, lowPart), highPart)));
            } else if (destSize == 4 && srcSize == 8 && op3.cls == REG) {
                /* VMOV Rd, Rn, Dm - double to two ARM regs */
                ExprId srcVal = il.Register(8, RegisterToIndex(srcReg));
                ConditionExecute(il, instr.cond,
                    il.SetRegister(4, RegisterToIndex(destReg),
                        il.LowPart(4, srcVal)));
                ConditionExecute(il, instr.cond,
                    il.SetRegister(4, RegisterToIndex(op3.reg),
                        il.LowPart(4, il.LogicalShiftRight(8, srcVal, il.Const(1, 32)))));
            } else {
                /* Other forms - simple move with size conversion */
                ConditionExecute(il, instr.cond,
                    il.SetRegister(destSize, RegisterToIndex(destReg),
                        srcSize > destSize
                            ? il.LowPart(destSize, il.Register(srcSize, RegisterToIndex(srcReg)))
                            : il.ZeroExtend(destSize, il.Register(srcSize, RegisterToIndex(srcReg)))));
            }
            return true;
        }

        case ARMV5_VADD: {
            /* VADD{cond}.F32/F64 Sd/Dd, Sn/Dn, Sm/Dm */
            size_t regSize = get_register_size(op1.reg);
            ConditionExecute(il, instr.cond,
                il.SetRegister(regSize, RegisterToIndex(op1.reg),
                    il.FloatAdd(regSize,
                        il.Register(regSize, RegisterToIndex(op2.reg)),
                        il.Register(regSize, RegisterToIndex(op3.reg)))));
            return true;
        }

        case ARMV5_VSUB: {
            /* VSUB{cond}.F32/F64 Sd/Dd, Sn/Dn, Sm/Dm */
            size_t regSize = get_register_size(op1.reg);
            ConditionExecute(il, instr.cond,
                il.SetRegister(regSize, RegisterToIndex(op1.reg),
                    il.FloatSub(regSize,
                        il.Register(regSize, RegisterToIndex(op2.reg)),
                        il.Register(regSize, RegisterToIndex(op3.reg)))));
            return true;
        }

        case ARMV5_VMUL:
        case ARMV5_VNMUL: {
            /* VMUL{cond}.F32/F64 Sd/Dd, Sn/Dn, Sm/Dm */
            size_t regSize = get_register_size(op1.reg);
            ExprId result = il.FloatMult(regSize,
                il.Register(regSize, RegisterToIndex(op2.reg)),
                il.Register(regSize, RegisterToIndex(op3.reg)));
            if (instr.operation == ARMV5_VNMUL)
                result = il.FloatNeg(regSize, result);
            ConditionExecute(il, instr.cond,
                il.SetRegister(regSize, RegisterToIndex(op1.reg), result));
            return true;
        }

        case ARMV5_VDIV: {
            /* VDIV{cond}.F32/F64 Sd/Dd, Sn/Dn, Sm/Dm */
            size_t regSize = get_register_size(op1.reg);
            ConditionExecute(il, instr.cond,
                il.SetRegister(regSize, RegisterToIndex(op1.reg),
                    il.FloatDiv(regSize,
                        il.Register(regSize, RegisterToIndex(op2.reg)),
                        il.Register(regSize, RegisterToIndex(op3.reg)))));
            return true;
        }

        case ARMV5_VNEG: {
            /* VNEG{cond}.F32/F64 Sd/Dd, Sm/Dm */
            size_t regSize = get_register_size(op1.reg);
            ConditionExecute(il, instr.cond,
                il.SetRegister(regSize, RegisterToIndex(op1.reg),
                    il.FloatNeg(regSize,
                        il.Register(regSize, RegisterToIndex(op2.reg)))));
            return true;
        }

        case ARMV5_VABS: {
            /* VABS{cond}.F32/F64 Sd/Dd, Sm/Dm */
            size_t regSize = get_register_size(op1.reg);
            ConditionExecute(il, instr.cond,
                il.SetRegister(regSize, RegisterToIndex(op1.reg),
                    il.FloatAbs(regSize,
                        il.Register(regSize, RegisterToIndex(op2.reg)))));
            return true;
        }

        case ARMV5_VSQRT: {
            /* VSQRT{cond}.F32/F64 Sd/Dd, Sm/Dm */
            size_t regSize = get_register_size(op1.reg);
            ConditionExecute(il, instr.cond,
                il.SetRegister(regSize, RegisterToIndex(op1.reg),
                    il.FloatSqrt(regSize,
                        il.Register(regSize, RegisterToIndex(op2.reg)))));
            return true;
        }

        case ARMV5_VCMP:
        case ARMV5_VCMPE: {
            /* VCMP{E}{cond}.F32/F64 Sd/Dd, Sm/Dm
             * Compare and set FPSCR flags - Binary Ninja doesn't have
             * a direct IL for this, use intrinsic */
            il.AddInstruction(il.Nop());
            return true;
        }

        case ARMV5_VCVT: {
            /* VCVT has many forms - float to int, int to float, etc.
             * For now, just handle basic float size conversions */
            size_t destSize = get_register_size(op1.reg);
            size_t srcSize = get_register_size(op2.reg);
            if (destSize != srcSize) {
                ConditionExecute(il, instr.cond,
                    il.SetRegister(destSize, RegisterToIndex(op1.reg),
                        il.FloatConvert(destSize,
                            il.Register(srcSize, RegisterToIndex(op2.reg)))));
            } else {
                /* Float to int or int to float - use intrinsic for now */
                ConditionExecute(il, instr.cond,
                    il.SetRegister(destSize, RegisterToIndex(op1.reg),
                        il.Register(srcSize, RegisterToIndex(op2.reg))));
            }
            return true;
        }

        case ARMV5_VMLA:
        case ARMV5_VMLS: {
            /* VMLA{cond}.F32/F64 Sd/Dd, Sn/Dn, Sm/Dm
             * Sd = Sd + Sn * Sm (MLA) or Sd = Sd - Sn * Sm (MLS) */
            size_t regSize = get_register_size(op1.reg);
            ExprId product = il.FloatMult(regSize,
                il.Register(regSize, RegisterToIndex(op2.reg)),
                il.Register(regSize, RegisterToIndex(op3.reg)));
            ExprId result;
            if (instr.operation == ARMV5_VMLA)
                result = il.FloatAdd(regSize,
                    il.Register(regSize, RegisterToIndex(op1.reg)), product);
            else
                result = il.FloatSub(regSize,
                    il.Register(regSize, RegisterToIndex(op1.reg)), product);
            ConditionExecute(il, instr.cond,
                il.SetRegister(regSize, RegisterToIndex(op1.reg), result));
            return true;
        }

        case ARMV5_VMRS:
            /* VMRS Rd, FPSCR - copy FPSCR to ARM register */
            if (op1.cls == REG && op2.cls == SYS_REG) {
                ConditionExecute(il, instr.cond,
                    il.SetRegister(4, RegisterToIndex(op1.reg),
                        il.Register(4, RegisterToIndex(op2.reg))));
            } else {
                il.AddInstruction(il.Unimplemented());
            }
            return true;

        case ARMV5_VMSR:
            /* VMSR FPSCR, Rd - copy ARM register to FPSCR */
            if (op1.cls == SYS_REG && op2.cls == REG) {
                ConditionExecute(il, instr.cond,
                    il.SetRegister(4, RegisterToIndex(op1.reg),
                        il.Register(4, RegisterToIndex(op2.reg))));
            } else {
                il.AddInstruction(il.Unimplemented());
            }
            return true;

        case ARMV5_FMSTAT:
            /* FMSTAT - copy VFP flags (FPSCR[31:28]) to APSR NZCV flags
             * This is VMRS APSR_nzcv, FPSCR but we model it specially */
            ConditionExecute(il, instr.cond,
                il.Intrinsic({}, ARMV5_INTRIN_MRS, {}));  /* Model as flag transfer */
            return true;

        /* Undefined */
        case ARMV5_UNDEFINED:
        case ARMV5_UDF:
            il.AddInstruction(il.Undefined());
            return true;

        default:
            il.AddInstruction(il.Unimplemented());
            return false;
    }
    return true;
}
