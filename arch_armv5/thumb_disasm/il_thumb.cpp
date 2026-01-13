#include <stdarg.h>
#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "il/il.h"
#include "spec.h"
#include "disassembler.h"

using namespace BinaryNinja;
using namespace armv5;

// align 32-bit number to 4
#define ALIGN4(a) ((a) & 0xFFFFFFFC)

bool GetLowLevelILForNEONInstruction(Architecture* arch, LowLevelILFunction& il, decomp_result* instr, bool ifThenBlock);

static uint32_t GetRegisterByIndex(uint32_t i, const char* prefix = "")
{
	if (strcmp(prefix, "s") == 0)
		return REG_S0 + i;
	if (strcmp(prefix, "d") == 0)
		return REG_D0 + i;
	// ARMv5 VFPv2 doesn't have Q registers (NEON is ARMv7+)
	return REG_R0 + i;
}

static uint32_t RegisterSizeFromPrefix(const char* prefix = "")
{
	if (strcmp(prefix, "s") == 0)
		return 4;
	if (strcmp(prefix, "d") == 0)
		return 8;
	if (strcmp(prefix, "q") == 0)
		return 16;
	return 4;
}

static ExprId ReadRegister(LowLevelILFunction& il, decomp_result* instr, uint32_t reg, size_t size = 4, const char* prefix = "", uint32_t align=0)
{
	if (reg == armv5::REG_PC && strcmp(prefix, "") == 0)
		return il.ConstPointer(size, instr->pc & (align ? ~(align - 1) : ~0));
	return il.Register(RegisterSizeFromPrefix(prefix), GetRegisterByIndex(reg, prefix));
}

static int GetSpecialRegister(LowLevelILFunction& il, decomp_result* instr, size_t operand)
{
	uint32_t mask = instr->fields[FIELD_mask] & 0xF;

	// ARMv5 only has CPSR and SPSR access
	if (IS_FIELD_PRESENT(instr, FIELD_write_spsr))
	{
		if (instr->fields[FIELD_write_spsr])
			return REGS_SPSR + mask;
		else
			return REGS_CPSR + mask;
	}

	// Default to CPSR for ARMv5
	return REGS_CPSR + mask;
}

static ExprId ReadILOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t size = 4)
{
	uint32_t value;
	uint64_t imm64;
	switch (instr->format->operands[operand].type)
	{
	case OPERAND_FORMAT_IMM64:
		imm64 = instr->fields[FIELD_imm64h];
		imm64 <<= 32;
		imm64 |= instr->fields[FIELD_imm64l];
		return il.Const(8, imm64);
	case OPERAND_FORMAT_IMM:
	case OPERAND_FORMAT_OPTIONAL_IMM:
		value = instr->fields[instr->format->operands[operand].field0];
		if ((instr->mnem == armv5::ARMV5_B) || (instr->mnem == armv5::ARMV5_BL))
		{
			value += instr->pc;
			return il.ConstPointer(size, value);
		}
		else if ((instr->mnem == armv5::ARMV5_BX) || (instr->mnem == armv5::ARMV5_BLX))
		{
			value += instr->pc & (~3);
			return il.ConstPointer(size, value);
		}
		return il.Const(size, value);
	case OPERAND_FORMAT_ADD_IMM:
	case OPERAND_FORMAT_OPTIONAL_ADD_IMM:
		value = instr->fields[instr->format->operands[operand].field0];
		if (instr->fields[FIELD_add])
			return il.Const(4, value);
		return il.Const(size, -(int64_t)value);
	case OPERAND_FORMAT_ZERO:
		return il.Const(size, 0);
	case OPERAND_FORMAT_REG:
		value = instr->fields[instr->format->operands[operand].field0];
		return ReadRegister(il, instr, GetRegisterByIndex(value), size, instr->format->operands[operand].prefix);
	case OPERAND_FORMAT_REG_FP:
		value = instr->fields[instr->format->operands[operand].field0];
		return ReadRegister(il, instr, value, size, instr->format->operands[operand].prefix);
	case OPERAND_FORMAT_SP:
		return il.Register(size, armv5::REG_SP);
	case OPERAND_FORMAT_LR:
		return il.Register(size, armv5::REG_LR);
	case OPERAND_FORMAT_PC:
		return il.ConstPointer(size, instr->pc);
	default:
		return il.Unimplemented();
	}
}

static uint32_t GetRegisterSize(decomp_result* instr, size_t operand)
{
	return RegisterSizeFromPrefix(instr->format->operands[operand].prefix);
}

static ExprId ReadShiftedOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t size = 4)
{
	uint32_t shift_t = instr->fields[FIELD_shift_t];
	uint32_t shift_n = instr->fields[FIELD_shift_n];
	ExprId value = ReadILOperand(il, instr, operand, size);

	if (shift_n == 0)
		return value;

	switch (shift_t)
	{
	case SRType_LSL:
		return il.ShiftLeft(size, value, il.Const(4, shift_n));
	case SRType_LSR:
		return il.LogicalShiftRight(size, value, il.Const(4, shift_n));
	case SRType_ASR:
		return il.ArithShiftRight(size, value, il.Const(4, shift_n));
	case SRType_RRX:
		return il.RotateRightCarry(size, value, il.Const(4, 1), il.Flag(IL_FLAG_C));
	case SRType_ROR:
		return il.RotateRight(size, value, il.Const(4, shift_n));
	default:
		return value;
	}
}

static ExprId ReadRotatedOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t size = 4)
{
	uint32_t rot_n = instr->fields[FIELD_rotation];
	ExprId value = ReadILOperand(il, instr, operand, size);

	if (IS_FIELD_PRESENT(instr, FIELD_rotation) && 0 != rot_n)
	{
		return il.RotateRight(size, value, il.Const(4, rot_n));
	}

	return value;
}

static ExprId ReadArithOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, size_t size = 4)
{
	if (operand == 0)
	{
		if (instr->format->operandCount == 2)
			return ReadILOperand(il, instr, 0, size);
		if ((instr->format->operandCount == 3) && (instr->format->operands[2].type == OPERAND_FORMAT_SHIFT))
			return ReadILOperand(il, instr, 0, size);
		return ReadILOperand(il, instr, 1, size);
	}

	if (instr->format->operandCount == 2)
		return ReadILOperand(il, instr, 1, size);
	if (instr->format->operandCount == 3)
	{
		if (instr->format->operands[2].type != OPERAND_FORMAT_SHIFT)
			return ReadILOperand(il, instr, 2, size);
		return ReadShiftedOperand(il, instr, 1, size);
	}
	return ReadShiftedOperand(il, instr, 2, size);
}

static uint32_t GetRegisterOperand(decomp_result* instr, size_t operand)
{
	uint32_t reg;
	switch (instr->format->operands[operand].type)
	{
		case OPERAND_FORMAT_REG:
			reg = instr->fields[instr->format->operands[operand].field0];
			return GetRegisterByIndex(reg);
		case OPERAND_FORMAT_REG_FP:
			reg = instr->fields[instr->format->operands[operand].field0];
			return GetRegisterByIndex(reg, instr->format->operands[operand].prefix);
		case OPERAND_FORMAT_SP:
			return armv5::REG_SP;
		case OPERAND_FORMAT_LR:
			return armv5::REG_LR;
		case OPERAND_FORMAT_PC:
			return armv5::REG_PC;
		default:
			return armv5::REG_INVALID;
	}
}

static ExprId WriteILOperand(LowLevelILFunction& il, decomp_result* instr, size_t operand, ExprId value,
	size_t size = 4, uint32_t flags = 0)
{
	uint32_t reg;
	switch (instr->format->operands[operand].type)
	{
	case OPERAND_FORMAT_REG:
		reg = instr->fields[instr->format->operands[operand].field0];
		if (reg == 15)
			return il.Jump(value);
		return il.SetRegister(size, GetRegisterByIndex(reg), value, flags);
	case OPERAND_FORMAT_REG_FP:
		reg = instr->fields[instr->format->operands[operand].field0];
		size = GetRegisterSize(instr, operand);
		return il.SetRegister(size, GetRegisterByIndex(reg, instr->format->operands[operand].prefix), value, flags);
	case OPERAND_FORMAT_SP:
		return il.SetRegister(size, armv5::REG_SP, value, flags);
	case OPERAND_FORMAT_LR:
		return il.SetRegister(size, armv5::REG_LR, value, flags);
	case OPERAND_FORMAT_PC:
		return il.Jump(value);
	default:
		return il.Unimplemented();
	}
}


static ExprId WriteArithOperand(LowLevelILFunction& il, decomp_result* instr, ExprId value, size_t size = 4,
	uint32_t flags = 0)
{
	return WriteILOperand(il, instr, 0, value, size, flags);
}


static ExprId WriteSplitOperands(LowLevelILFunction& il, decomp_result *instr, size_t operandHi, size_t operandLo, ExprId value,
	size_t size = 4, uint32_t flags = 0)
{
	uint32_t regHi = instr->fields[instr->format->operands[operandHi].field0];
	uint32_t regLo = instr->fields[instr->format->operands[operandLo].field0];

	return il.SetRegisterSplit(size, GetRegisterByIndex(regHi), GetRegisterByIndex(regLo), value, flags);
}


static bool HasWriteback(decomp_result* instr, size_t operand)
{
	switch (instr->format->operands[operand].writeback)
	{
	case WRITEBACK_YES:
		return true;
	case WRITEBACK_OPTIONAL:
		return thumb_has_writeback(instr);
	default:
		return false;
	}
}


static ExprId ShiftedRegister(LowLevelILFunction& il, decomp_result* instr, uint32_t reg, uint32_t t, uint32_t n)
{
	if (n == 0)
		return il.Register(4, reg);
	switch (t)
	{
	case SRType_LSL:
		return il.ShiftLeft(4, ReadRegister(il, instr, reg), il.Const(4, n));
	case SRType_LSR:
		return il.LogicalShiftRight(4, ReadRegister(il, instr, reg), il.Const(4, n));
	case SRType_ASR:
		return il.ArithShiftRight(4, ReadRegister(il, instr, reg), il.Const(4, n));
	case SRType_ROR:
		return il.RotateRight(4, ReadRegister(il, instr, reg), il.Const(4, n));
	case SRType_RRX:
		return il.RotateRightCarry(4, ReadRegister(il, instr, reg), il.Const(4, 1), il.Flag(IL_FLAG_C));
	default:
		return il.Unimplemented();
	}
}

#define ReadRegisterA(il, instr, reg, align) ReadRegister(il, instr, reg, 4, "", align)
static ExprId GetMemoryAddress(LowLevelILFunction& il, decomp_result* instr, size_t operand, uint32_t size,
	bool canWriteback = true, uint32_t align=0)
{
	uint32_t reg, second, t, n;
	switch (instr->format->operands[operand].type)
	{
	case OPERAND_FORMAT_MEMORY_ONE_REG:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		return il.Register(4, reg);
	case OPERAND_FORMAT_MEMORY_ONE_REG_IMM:
	case OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = instr->fields[instr->format->operands[operand].field1];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_ONE_REG_NEG_IMM:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = instr->fields[instr->format->operands[operand].field1];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Sub(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second))));
			return il.Register(4, reg);
		}
		return il.Sub(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_ONE_REG_ADD_IMM:
	case OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_ADD_IMM:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = instr->fields[instr->format->operands[operand].field1];
		if (canWriteback && HasWriteback(instr, operand))
		{
			if (instr->fields[FIELD_add])
				il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second))));
			else
				il.AddInstruction(il.SetRegister(4, reg, il.Sub(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second))));
			return il.Register(4, reg);
		}
		if (instr->fields[FIELD_add])
			return il.Add(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second));
		return il.Sub(4, ReadRegisterA(il, instr, reg, align), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_TWO_REG:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field1]);
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegisterA(il, instr, reg, align), il.Register(4, second))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegisterA(il, instr, reg, align), il.Register(4, second));
	case OPERAND_FORMAT_MEMORY_TWO_REG_SHIFT:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field1]);
		t = instr->fields[FIELD_shift_t];
		n = instr->fields[FIELD_shift_n];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegisterA(il, instr, reg, align),
				ShiftedRegister(il, instr, second, t, n))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegisterA(il, instr, reg, align), ShiftedRegister(il, instr, second, t, n));
	case OPERAND_FORMAT_MEMORY_TWO_REG_LSL_ONE:
		reg = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field0]);
		second = GetRegisterByIndex(instr->fields[instr->format->operands[operand].field1]);
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, ReadRegisterA(il, instr, reg, align),
				il.ShiftLeft(4, ReadRegister(il, instr, second), il.Const(4, 1)))));
			return il.Register(4, reg);
		}
		return il.Add(4, ReadRegisterA(il, instr, reg, align), il.ShiftLeft(4, ReadRegister(il, instr, second), il.Const(4, 1)));
	case OPERAND_FORMAT_MEMORY_SP_IMM:
	case OPERAND_FORMAT_MEMORY_SP_OPTIONAL_IMM:
		second = instr->fields[instr->format->operands[operand].field0];
		if (canWriteback && HasWriteback(instr, operand))
		{
			il.AddInstruction(il.SetRegister(4, armv5::REG_SP, il.Add(4, il.Register(4, armv5::REG_SP), il.Const(4, second))));
			return il.Register(4, armv5::REG_SP);
		}
		return il.Add(4, il.Register(4, armv5::REG_SP), il.Const(4, second));
	case OPERAND_FORMAT_MEMORY_PC:
		return il.ConstPointer(4, instr->pc & (align ? ~(align - 1) : ~0));
	case OPERAND_FORMAT_LABEL:
		if (instr->fields[FIELD_add])
			return il.ConstPointer(4, ALIGN4(instr->pc) + instr->fields[FIELD_imm32]);
		return il.ConstPointer(4, ALIGN4(instr->pc) - instr->fields[FIELD_imm32]);
	default:
		return il.Unimplemented();
	}
}


// Note: GetCondition is defined in il/il.cpp and declared in il/il.h


static void ConditionalJump(Architecture* arch, LowLevelILFunction& il, uint32_t cond, uint32_t t, uint32_t f)
{
	BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
	BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);

	if (trueLabel && falseLabel)
	{
		il.AddInstruction(il.If(GetCondition(il, cond), *trueLabel, *falseLabel));
		return;
	}

	LowLevelILLabel trueCode, falseCode;

	if (trueLabel)
	{
		il.AddInstruction(il.If(GetCondition(il, cond), *trueLabel, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(4, f)));
		return;
	}

	if (falseLabel)
	{
		il.AddInstruction(il.If(GetCondition(il, cond), trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(4, t)));
		return;
	}

	il.AddInstruction(il.If(GetCondition(il, cond), trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(il.Jump(il.ConstPointer(4, t)));
	il.MarkLabel(falseCode);
	il.AddInstruction(il.Jump(il.ConstPointer(4, f)));
}


static void CompareWithZeroAndConditionalJump(Architecture* arch, LowLevelILFunction& il, uint32_t reg,
	BNLowLevelILOperation cond, uint32_t t, uint32_t f)
{
	BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
	BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);
	ExprId condExpr = il.AddExpr(cond, 4, 0, il.Register(4, GetRegisterByIndex(reg)), il.Const(4, 0));

	if (trueLabel && falseLabel)
	{
		il.AddInstruction(il.If(condExpr, *trueLabel, *falseLabel));
		return;
	}

	LowLevelILLabel trueCode, falseCode;

	if (trueLabel)
	{
		il.AddInstruction(il.If(condExpr, *trueLabel, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(4, f)));
		return;
	}

	if (falseLabel)
	{
		il.AddInstruction(il.If(condExpr, trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(4, t)));
		return;
	}

	il.AddInstruction(il.If(condExpr, trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(il.Jump(il.ConstPointer(4, t)));
	il.MarkLabel(falseCode);
	il.AddInstruction(il.Jump(il.ConstPointer(4, f)));
}


void SetupThumbConditionalInstructionIL(LowLevelILFunction& il, LowLevelILLabel& trueLabel,
	LowLevelILLabel& falseLabel, uint32_t cond)
{
	il.AddInstruction(il.If(GetCondition(il, cond), trueLabel, falseLabel));
}


static void Push(LowLevelILFunction& il, uint32_t regs)
{
	for (int32_t i = 15; i >= 0; i--)
	{
		if (((regs >> i) & 1) == 1)
		{
			il.AddInstruction(il.Push(4, il.Register(4, GetRegisterByIndex(i))));
		}
	}
}


static void Pop(LowLevelILFunction& il, uint32_t regs)
{
	for (int32_t i = 0; i <= 15; i++)
	{
		if (((regs >> i) & 1) == 1)
		{
			if (i == 15)
				il.AddInstruction(il.Return(il.Pop(4)));
			else
				il.AddInstruction(il.SetRegister(4, GetRegisterByIndex(i), il.Pop(4)));
		}
	}
}


static bool WritesToStatus(decomp_result* instr, bool ifThenBlock)
{
	if (ifThenBlock)
		return false;
	if (instr->format->operationFlags & INSTR_FORMAT_FLAG_OPTIONAL_STATUS)
	{
		if (IS_FIELD_PRESENT(instr, FIELD_S))
		{
			if (instr->fields[FIELD_S])
				return true;
		}
	}
	return false;
}

static bool IsPCRelativeDataAddress(decomp_result* instr, bool ifThenBlock)
{
	if ((instr->format->operandCount == 3) && (instr->format->operands[1].type == OPERAND_FORMAT_PC)
		&& (instr->format->operands[2].type == OPERAND_FORMAT_IMM) && !WritesToStatus(instr, ifThenBlock))
		return true;

	return false;
}


bool GetLowLevelILForThumbInstruction(Architecture* arch, LowLevelILFunction& il, decomp_result* instr)
{
	// Note: ARMv5 Thumb doesn't have IT blocks, so ifThenBlock is always false
	bool ifThenBlock = false;

	if ((instr->status & STATUS_UNDEFINED) || (!instr->format))
		return false;

	switch (instr->mnem)
	{
	case armv5::ARMV5_ADC:
		il.AddInstruction(WriteArithOperand(il, instr,
			il.AddCarry(4, ReadArithOperand(il, instr, 0), ReadArithOperand(il, instr, 1), il.Flag(IL_FLAG_C),
				WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv5::ARMV5_ADCS:
		il.AddInstruction(WriteArithOperand(il, instr,
			il.AddCarry(4, ReadArithOperand(il, instr, 0), ReadArithOperand(il, instr, 1), il.Flag(IL_FLAG_C),
				ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv5::ARMV5_ADD:
		if (IsPCRelativeDataAddress(instr, ifThenBlock))
			il.AddInstruction(WriteArithOperand(il, instr, il.Add(4, il.And(4, ReadILOperand(il, instr, 1, 4), il.Const(4, ~3)),
				ReadILOperand(il, instr, 2, 4))));
		else
			il.AddInstruction(WriteArithOperand(il, instr, il.Add(4, ReadArithOperand(il, instr, 0),
				ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv5::ARMV5_ADDS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Add(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv5::ARMV5_ADR:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.ConstPointer(4, (instr->pc + instr->fields[
			instr->format->operands[1].field0]) & (~3))));
		break;
	case armv5::ARMV5_AND:
		il.AddInstruction(WriteArithOperand(il, instr, il.And(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv5::ARMV5_ANDS:
		il.AddInstruction(WriteArithOperand(il, instr, il.And(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv5::ARMV5_ASR:
		il.AddInstruction(WriteArithOperand(il, instr, il.ArithShiftRight(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_CNZ : 0)));
		break;
	case armv5::ARMV5_ASRS:
		il.AddInstruction(WriteArithOperand(il, instr, il.ArithShiftRight(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_CNZ)));
		break;
	case armv5::ARMV5_B:
		if ((!(instr->format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL)) ||
			(instr->fields[FIELD_cond] == COND_AL))
		{
			uint32_t dest = instr->pc + instr->fields[instr->format->operands[0].field0];
			BNLowLevelILLabel* label = il.GetLabelForAddress(arch, dest);
			if (label)
				il.AddInstruction(il.Goto(*label));
			else
				il.AddInstruction(il.Jump(il.ConstPointer(4, dest)));
		}
		else
		{
			uint32_t t = instr->pc + instr->fields[instr->format->operands[0].field0];
			uint32_t f = (instr->pc - 4) + (instr->instrSize / 8);
			ConditionalJump(arch, il, instr->fields[FIELD_cond], t, f);
		}
		break;
	// Note: BFC and BFI are ARMv6T2+ (Thumb-2) - removed for ARMv5
	case armv5::ARMV5_BIC:
		il.AddInstruction(WriteArithOperand(il, instr, il.And(4, ReadArithOperand(il, instr, 0),
			il.Not(4, ReadArithOperand(il, instr, 1)), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv5::ARMV5_BICS:
		il.AddInstruction(WriteArithOperand(il, instr, il.And(4, ReadArithOperand(il, instr, 0),
			il.Not(4, ReadArithOperand(il, instr, 1)), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv5::ARMV5_BKPT:
		il.AddInstruction(il.Breakpoint());
		break;
	case armv5::ARMV5_BL:
	case armv5::ARMV5_BLX:
		il.AddInstruction(il.Call(ReadILOperand(il, instr, 0)));
		break;
	case armv5::ARMV5_BX:
		if ((instr->format->operands[0].type == OPERAND_FORMAT_LR) ||
			(instr->fields[instr->format->operands[0].field0] == 14))
		{
			il.AddInstruction(il.Return(il.Register(4, armv5::REG_LR)));
		}
		else
		{
			il.AddInstruction(il.Jump(ReadRegister(il, instr, GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]), 4)));
		}
		break;
	// Note: CBNZ and CBZ are ARMv6T2+ (Thumb-2) - removed for ARMv5
	/* CLZ - Count Leading Zeros
	 * Lifted as a loop using native LLIL operations (no intrinsic).
	 * This allows WARP and other analysis passes to properly track values.
	 *
	 *   temp0 = 0 (counter)
	 *   temp1 = Rm (input)
	 * loop:
	 *   if (temp1 != 0) then { temp1 >>= 1; temp0++; goto loop; }
	 *   Rd = 32 - temp0
	 */
	case armv5::ARMV5_CLZ:
		{
			LowLevelILLabel loopStart, loopBody, loopExit;

			// temp0 = 0 (bit counter)
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Const(4, 0)));
			// temp1 = Rm (working copy)
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1), ReadILOperand(il, instr, 1)));

			// Loop start
			il.MarkLabel(loopStart);
			// if (temp1 != 0) goto loopBody else loopExit
			il.AddInstruction(il.If(
				il.CompareNotEqual(4, il.Register(4, LLIL_TEMP(1)), il.Const(4, 0)),
				loopBody, loopExit));

			// Loop body: shift right and increment counter
			il.MarkLabel(loopBody);
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(1),
				il.LogicalShiftRight(4, il.Register(4, LLIL_TEMP(1)), il.Const(4, 1))));
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0),
				il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 1))));
			il.AddInstruction(il.Goto(loopStart));

			// Loop done: Rd = 32 - temp0
			il.MarkLabel(loopExit);
			il.AddInstruction(WriteILOperand(il, instr, 0,
				il.Sub(4, il.Const(4, 32), il.Register(4, LLIL_TEMP(0)))));
			break;
		}
	case armv5::ARMV5_CMP:
		il.AddInstruction(il.Sub(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1), IL_FLAGWRITE_ALL));
		break;
	case armv5::ARMV5_CMN:
		il.AddInstruction(il.Add(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1), IL_FLAGWRITE_ALL));
		break;
	// Note: DBG, DMB, DSB are ARMv7 barrier instructions - removed for ARMv5
	case armv5::ARMV5_EOR:
		il.AddInstruction(WriteArithOperand(il, instr, il.Xor(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv5::ARMV5_EORS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Xor(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	// Note: ISB is ARMv7 barrier instruction - removed for ARMv5
	case ARMV5_LDM:
	case ARMV5_LDMIA:
	case ARMV5_LDMDB:
	{
		bool decBeforeMode = instr->mnem == ARMV5_LDMDB;
		bool is16BitForm = (instr->instrSize == 16);
		uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
		uint32_t regs = instr->fields[instr->format->operands[1].field0];
		uint32_t lrpcBits = (1 << armv5::REG_LR) | (1 << armv5::REG_PC);
		bool valid = true;
		if (baseReg == armv5::REG_PC)
			valid = false;
		else if (!is16BitForm)
		{
			if (((regs & (1 << armv5::REG_SP)) || (regs & (1 << armv5::REG_PC)) || ((regs & lrpcBits) == lrpcBits) || !(regs & (regs - 1)) || (HasWriteback(instr, 0) && (regs & (1 << baseReg)))))
				valid = false;
		}
		else // is16BitForm
		{
			if (decBeforeMode)
				valid = false;
			else if (!HasWriteback(instr, 0) && !(regs & (1 << baseReg)))
				valid = false;
		}

		if (!valid)
		{
			il.AddInstruction(il.Undefined());
			break;
		}

		int32_t regLimit = is16BitForm ? 7 : 15;
		int32_t regCnt = 0;
		bool baseIsNotFirst = true;
		for (int32_t i = 0; i <= regLimit; i++)
		{
			if ((regs >> i) & 1)
			{
				if (!regCnt && (i == baseReg))
					baseIsNotFirst = false;
				regCnt++;
			}
		}

		if (decBeforeMode)
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Add(4, il.Register(4, baseReg), il.Const(4, regCnt * -4))));
		else
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Register(4, baseReg)));

		for (int32_t i = 0, slot = 0; i <= regLimit; i++)
		{
			if ((regs >> i) & 1)
			{
				il.AddInstruction(il.SetRegister(4, GetRegisterByIndex(i),
					il.Load(4, il.Add(4, il.Register(4, LLIL_TEMP(0)), il.Const(4, 4 * slot++)))));
			}
		}

		if (HasWriteback(instr, 0) && baseIsNotFirst)
		{
			if (decBeforeMode)
				il.AddInstruction(il.SetRegister(4, baseReg, il.Register(4, LLIL_TEMP(0))));
			else
				il.AddInstruction(il.SetRegister(4, baseReg,
					il.Add(4, ReadRegister(il, instr, baseReg), il.Const(4, regCnt * 4))));
		}

		if (regs & (1 << armv5::REG_PC))
			il.AddInstruction(il.Jump(ReadRegister(il, instr, armv5::REG_PC, 4)));
		break;
	}
	// Note: LDA and LDREX are ARMv6/ARMv7 instructions - removed for ARMv5
	case armv5::ARMV5_LDR:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(WriteILOperand(il, instr, 0, il.Load(4, GetMemoryAddress(il, instr, 1, 4, false))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, il.Load(4, GetMemoryAddress(il, instr, 1, 4))));
		}
		break;
	// Note: LDAB and LDREXB are ARMv6/ARMv7 instructions
	case armv5::ARMV5_LDRB:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(WriteILOperand(il, instr, 0, il.ZeroExtend(4,
				il.Load(1, GetMemoryAddress(il, instr, 1, 4, false)))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, il.ZeroExtend(4,
				il.Load(1, GetMemoryAddress(il, instr, 1, 4)))));
		}
		break;
	// Note: LDAH and LDREXH are ARMv6/ARMv7 instructions
	case armv5::ARMV5_LDRH:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(WriteILOperand(il, instr, 0, il.ZeroExtend(4,
				il.Load(2, GetMemoryAddress(il, instr, 1, 4, false)))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, il.ZeroExtend(4,
				il.Load(2, GetMemoryAddress(il, instr, 1, 4)))));
		}
		break;
	// Note: LDREXD is ARMv6K/ARMv7 instruction
	case armv5::ARMV5_LDRD:
	{
		ExprId mem;

		uint32_t rt = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
		uint32_t rt2 = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);

		mem = GetMemoryAddress(il, instr, 2, 4, instr->format->operandCount != 4);
		if (arch->GetEndianness() == LittleEndian)
		{
				il.AddInstruction(il.SetRegister(4, rt, il.Load(4, mem)));
				il.AddInstruction(il.SetRegister(4, rt2, il.Load(4, il.Add(4, mem, il.Const(4, 4)))));
		}
		else
		{
			il.AddInstruction(il.SetRegister(4, rt2, il.Load(4, mem)));
			il.AddInstruction(il.SetRegister(4, rt, il.Load(4, il.Add(4, mem, il.Const(4, 4)))));
		}

		if (instr->format->operandCount == 4)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[2].field0]);
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 3))));
		}
		break;
	}
	case armv5::ARMV5_LDRSB:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(WriteILOperand(il, instr, 0, il.SignExtend(4,
				il.Load(1, GetMemoryAddress(il, instr, 1, 4, false)))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, il.SignExtend(4,
				il.Load(1, GetMemoryAddress(il, instr, 1, 4)))));
		}
		break;
	case armv5::ARMV5_LDRSH:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(WriteILOperand(il, instr, 0, il.SignExtend(4,
				il.Load(2, GetMemoryAddress(il, instr, 1, 4, false)))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0, il.SignExtend(4,
				il.Load(2, GetMemoryAddress(il, instr, 1, 4)))));
		}
		break;
	case armv5::ARMV5_LSL:
		il.AddInstruction(WriteArithOperand(il, instr, il.ShiftLeft(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_CNZ : 0)));
		break;
	case armv5::ARMV5_LSLS:
		il.AddInstruction(WriteArithOperand(il, instr, il.ShiftLeft(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_CNZ)));
		break;
	case armv5::ARMV5_LSR:
		il.AddInstruction(WriteArithOperand(il, instr, il.LogicalShiftRight(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_CNZ : 0)));
		break;
	case armv5::ARMV5_LSRS:
		il.AddInstruction(WriteArithOperand(il, instr, il.LogicalShiftRight(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_CNZ)));
		break;
	// Note: MCR2 is ARMv5TE+ but uses same encoding
	case armv5::ARMV5_MCR:
	{
		int dest_reg_field = instr->fields[instr->format->operands[2].field0];
		int dest_reg = GetRegisterByIndex(dest_reg_field, instr->format->operands[2].prefix);

		il.AddInstruction(
			il.Intrinsic({ }, ARMV5_INTRIN_COPROC_SENDONEWORD,
				{
					il.Register(4, dest_reg),
					il.Const(1, instr->fields[instr->format->operands[0].field0]),
					il.Const(1, instr->fields[instr->format->operands[1].field0]),
					il.Const(1, instr->fields[instr->format->operands[3].field0]),
					il.Const(1, instr->fields[instr->format->operands[4].field0]),
					il.Const(1, instr->fields[instr->format->operands[5].field0]),
				}
			)
		);
		break;
	}
	// Note: MCRR2 is ARMv6+
	case ARMV5_MCRR:
	{
		int rt = instr->fields[instr->format->operands[2].field0];
		int rt2 = instr->fields[instr->format->operands[3].field0];
		il.AddInstruction(
			il.Intrinsic({ }, ARMV5_INTRIN_COPROC_SENDTWOWORDS,
				{
					il.Register(4, rt2),
					il.Register(4, rt),
					il.Const(1, instr->fields[instr->format->operands[0].field0]),
					il.Const(1, instr->fields[instr->format->operands[1].field0]),
					il.Const(1, instr->fields[instr->format->operands[4].field0]),
				}
			)
		);
		break;
	}
	case armv5::ARMV5_MLA:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Add(4, ReadILOperand(il, instr, 3), il.Mult(4, ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2)))));
		break;
	// Note: MLS is ARMv6T2+
	case armv5::ARMV5_MOV:
		il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1), 4,
			WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_NZ : 0));
		break;
	case armv5::ARMV5_MOVS:
		il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1), 4,
			ifThenBlock ? 0 : IL_FLAGWRITE_NZ));
		break;
	// Note: MOVT is ARMv6T2+, MRC2 is ARMv5TE+
	case armv5::ARMV5_MRC:
	{
		auto params = {
			il.Const(1, instr->fields[instr->format->operands[0].field0]), /* cp */
			il.Const(1, instr->fields[instr->format->operands[1].field0]), /* opc1 */
			il.Const(1, instr->fields[instr->format->operands[3].field0]), /* crn */
			il.Const(1, instr->fields[instr->format->operands[4].field0]), /* crm */
			il.Const(1, instr->fields[instr->format->operands[5].field0]), /* opc2 */
		};

		int dest_reg_field = instr->fields[instr->format->operands[2].field0];
		if (dest_reg_field == 15)
		{
			il.AddInstruction(
				il.Intrinsic(
					{ RegisterOrFlag::Register(LLIL_TEMP(0)) },
					ARMV5_INTRIN_COPROC_GETONEWORD,
					params
				)
			);
			il.AddInstruction(il.SetFlag(IL_FLAG_N, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 31))));
			il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 30))));
			il.AddInstruction(il.SetFlag(IL_FLAG_C, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 29))));
			il.AddInstruction(il.SetFlag(IL_FLAG_V, il.TestBit(4, il.Register(4, LLIL_TEMP(0)), il.Const(1, 28))));
			break;
		}

		int dest_reg = GetRegisterByIndex(dest_reg_field, instr->format->operands[2].prefix);

		il.AddInstruction(
			il.Intrinsic(
				{RegisterOrFlag::Register(dest_reg)}, /* outputs */
				ARMV5_INTRIN_COPROC_GETONEWORD,
				params /* inputs */
			)
		);
		break;
	}

	// Note: MRRC2 is ARMv6+
	case ARMV5_MRRC:
	{
		int rt = instr->fields[instr->format->operands[2].field0];
		int rt2 = instr->fields[instr->format->operands[3].field0];

		il.AddInstruction(
			il.Intrinsic(
				{ RegisterOrFlag::Register(rt2), RegisterOrFlag::Register(rt) },
				ARMV5_INTRIN_COPROC_GETTWOWORDS,
				{
					il.Const(1, instr->fields[instr->format->operands[0].field0]),
					il.Const(1, instr->fields[instr->format->operands[1].field0]),
					il.Const(1, instr->fields[instr->format->operands[4].field0]),
				}
			)
		);
		break;
	}

	case armv5::ARMV5_MRS:
	{
		int dest_reg = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0], instr->format->operands[0].prefix);

		int intrinsic_id = ARMV5_INTRIN_MRS;

		il.AddInstruction(
			il.Intrinsic(
				{RegisterOrFlag::Register(dest_reg)}, /* outputs */
				intrinsic_id,
				// {il.Register(4, GetSpecialRegister(il, instr, 1))} /* inputs */
				{il.Const(4, GetSpecialRegister(il, instr, 1))} /* inputs */
			)
		);
		break;
	}
	case armv5::ARMV5_MSR:
	{
		int dest_reg = GetSpecialRegister(il, instr, 0);
		int intrinsic_id = ARMV5_INTRIN_MSR;

		il.AddInstruction(
			il.Intrinsic(
				{}, /* outputs */
				intrinsic_id,
				{
					// il.Register(4, dest_reg),
					il.Const(4, dest_reg),
					ReadILOperand(il, instr, 1)
				} /* inputs */
			)
		);


		/* certain MSR scenarios earn a specialized intrinsic */
		// if (dest_reg == REGS_BASEPRI)
		// 	intrinsic_id = ARM_M_INTRIN_SET_BASEPRI;
		// switch (dest_reg) {
		// 	case REGS_MSP:
		// 	case REGS_PSP:
		// 	case REGS_BASEPRI:
		// 	case REGS_BASEPRI_MAX:
		// 	case REGS_PRIMASK:
		// 	case REGS_FAULTMASK:
		// 	case REGS_CONTROL:
		// 	case REGS_IPSR:
		// 	case REGS_EPSR:
		// 	case REGS_IEPSR:
		// 		il.AddInstruction(
		// 			il.Intrinsic(
		// 				{}, /* outputs */
		// 				intrinsic_id,
		// 				{
		// 					// il.Register(4, dest_reg),
		// 					il.Const(4, dest_reg),
		// 					ReadILOperand(il, instr, 1)
		// 				} /* inputs */
		// 			)
		// 		);
		// 		break;
		// 	default:
		// 		il.AddInstruction(
		// 			il.Intrinsic(
		// 				{RegisterOrFlag::Register(dest_reg)}, /* outputs */
		// 				intrinsic_id,
		// 				{ReadILOperand(il, instr, 1)} /* inputs */
		// 			)
		// 		);
		// }

		break;
	}
	case armv5::ARMV5_MUL:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_NZ : 0)));
		break;
	case armv5::ARMV5_MULS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_NZ)));
		break;
	case armv5::ARMV5_MVN:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Not(4, ReadArithOperand(il, instr, 1),
			WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv5::ARMV5_MVNS:
		il.AddInstruction(WriteILOperand(il, instr, 0, il.Not(4, ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv5::ARMV5_NOP:
		il.AddInstruction(il.Nop());
		break;
	// Note: ORN is ARMv6T2+ (Thumb-2 only)
	case armv5::ARMV5_ORR:
		il.AddInstruction(WriteArithOperand(il, instr, il.Or(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv5::ARMV5_ORRS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Or(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	case armv5::ARMV5_POP:
		Pop(il, instr->fields[FIELD_registers]);
		break;
	case armv5::ARMV5_PUSH:
		Push(il, instr->fields[FIELD_registers]);
		break;
	// Note: RBIT, REV, REV16 are ARMv6+ only (not in ARMv5)
    case armv5::ARMV5_ROR:
        il.AddInstruction(WriteArithOperand(il, instr, il.RotateRight(4, ReadArithOperand(il, instr, 0),
            ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
        break;
    case armv5::ARMV5_RORS:
        il.AddInstruction(WriteArithOperand(il, instr, il.RotateRight(4, ReadArithOperand(il, instr, 0),
            ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
        break;
	case armv5::ARMV5_RSB:
		il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, ReadArithOperand(il, instr, 1),
			ReadArithOperand(il, instr, 0), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv5::ARMV5_RSBS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, ReadArithOperand(il, instr, 1),
			ReadArithOperand(il, instr, 0), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	// Note: UADD8, UADD16, UDIV, SDIV are ARMv6+ or ARMv7+ only (not in ARMv5)
	case armv5::ARMV5_SBC:
		il.AddInstruction(WriteArithOperand(il, instr, il.SubBorrow(4, ReadArithOperand(il, instr, 0),
									       ReadArithOperand(il, instr, 1),
									       il.Not(1, il.Flag(IL_FLAG_C)),
									       WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv5::ARMV5_SBCS:
		il.AddInstruction(WriteArithOperand(il, instr, il.SubBorrow(4, ReadArithOperand(il, instr, 0),
									       ReadArithOperand(il, instr, 1),
									       il.Not(1, il.Flag(IL_FLAG_C)),
									       ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
	// Note: SBFX, SEV are ARMv6T2+ only (not in ARMv5)
	case ARMV5_STM:
	case ARMV5_STMIA:
	case ARMV5_STMDB:
	{
		bool decBeforeMode = instr->mnem == ARMV5_STMDB;
		bool is16BitForm = (instr->instrSize == 16);
		uint32_t baseReg = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
		uint32_t regs = instr->fields[instr->format->operands[1].field0];
		bool valid = true;
		if (baseReg == armv5::REG_PC)
			valid = false;
		else if (!is16BitForm)
		{
			if (((regs & (1 << armv5::REG_SP)) || (regs & (1 << armv5::REG_PC)) || !(regs & (regs - 1)) || (HasWriteback(instr, 0) && (regs & (1 << baseReg)))))
				valid = false;
		}
		else // is16BitForm
		{
			if (decBeforeMode || !HasWriteback(instr, 0))
				valid = false;
			// TODO technically not allowed...perhaps add a tag for indication of cases like this
			// else if ((regs & (1 << baseReg)) && (((1 << baseReg) - 1) & regs))
			// 	valid = false;
		}

		if (!valid)
		{
			il.AddInstruction(il.Undefined());
			break;
		}

		int32_t regLimit = is16BitForm ? 7 : 15;
		int32_t regCnt = 0;
		bool baseIsNotFirst = true;
		for (int32_t i = 0; i <= regLimit; i++)
		{
			if ((regs >> i) & 1)
			{
				if (!regCnt && (i == baseReg))
					baseIsNotFirst = false;
				regCnt++;
			}
		}

		if (decBeforeMode)
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Add(4, il.Register(4, baseReg), il.Const(4, regCnt * -4))));
		else
			il.AddInstruction(il.SetRegister(4, LLIL_TEMP(0), il.Register(4, baseReg)));

		uint32_t targetReg = decBeforeMode ? LLIL_TEMP(0) : baseReg;
		for (int32_t i = 0, slot = 0; i <= regLimit; i++)
		{
			if ((regs >> i) & 1)
			{
				il.AddInstruction(il.Store(4,
					il.Add(4, il.Register(4, targetReg), il.Const(4, 4 * slot++)),
						il.Register(4, GetRegisterByIndex(i))));
			}
		}

		if (HasWriteback(instr, 0) && baseIsNotFirst)
		{
			if (decBeforeMode)
				il.AddInstruction(il.SetRegister(4, baseReg, il.Register(4, LLIL_TEMP(0))));
			else
				il.AddInstruction(il.SetRegister(4, baseReg,
					il.Add(4, ReadRegister(il, instr, baseReg), il.Const(4, regCnt * 4))));
		}

		if (regs & (1 << armv5::REG_PC))
			il.AddInstruction(il.Jump(ReadRegister(il, instr, armv5::REG_PC, 4)));
		break;
	}
	// Note: STL is ARMv8+ only (not in ARMv5)
	case armv5::ARMV5_STR:
	// case armv5::ARMV5_STREX:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(il.Store(4, GetMemoryAddress(il, instr, 1, 4, false), ReadILOperand(il, instr, 0)));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(il.Store(4, GetMemoryAddress(il, instr, 1, 4), ReadILOperand(il, instr, 0)));
		}
		break;
	// Note: STLB is ARMv8+ only (not in ARMv5)
	case armv5::ARMV5_STRB:
	// case armv5::ARMV5_STREXB:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(il.Store(1, GetMemoryAddress(il, instr, 1, 4, false), il.LowPart(1, ReadILOperand(il, instr, 0))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(il.Store(1, GetMemoryAddress(il, instr, 1, 4), il.LowPart(1, ReadILOperand(il, instr, 0))));
		}
		break;
	// Note: STLH is ARMv8+ only (not in ARMv5)
	case armv5::ARMV5_STRH:
	// case armv5::ARMV5_STREXH:
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
			il.AddInstruction(il.Store(2, GetMemoryAddress(il, instr, 1, 4, false), il.LowPart(2, ReadILOperand(il, instr, 0))));
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(il.Store(2, GetMemoryAddress(il, instr, 1, 4), il.LowPart(2, ReadILOperand(il, instr, 0))));
		}
		break;
	case armv5::ARMV5_STRD:
	// case armv5::ARMV5_STREXD:
	{
		ExprId mem;

		mem = GetMemoryAddress(il, instr, 2, 4, instr->format->operandCount != 4);
		if (arch->GetEndianness() == LittleEndian)
		{
			il.AddInstruction(il.Store(4, mem, ReadILOperand(il, instr, 0)));
			il.AddInstruction(il.Store(4, il.Add(4, mem, il.Const(4, 4)), ReadILOperand(il, instr, 1)));
		}
		else
		{
			il.AddInstruction(il.Store(4, mem, ReadILOperand(il, instr, 1)));
			il.AddInstruction(il.Store(4, il.Add(4, mem, il.Const(4, 4)), ReadILOperand(il, instr, 0)));
		}

		if (instr->format->operandCount == 4)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[2].field0]);
			il.AddInstruction(il.SetRegister(4, reg, il.Add(4, il.Register(4, reg), ReadILOperand(il, instr, 3))));
		}
		break;
	}
	// Note: SUBW is Thumb-2 only (ARMv6T2+)
	case armv5::ARMV5_SUB:
		if (IsPCRelativeDataAddress(instr, ifThenBlock))
			il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, il.And(4, ReadILOperand(il, instr, 1, 4), il.Const(4, ~3)),
				ReadILOperand(il, instr, 2, 4))));
		else
			il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, ReadArithOperand(il, instr, 0),
				ReadArithOperand(il, instr, 1), WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_ALL : 0)));
		break;
	case armv5::ARMV5_SUBS:
		il.AddInstruction(WriteArithOperand(il, instr, il.Sub(4, ReadArithOperand(il, instr, 0),
			ReadArithOperand(il, instr, 1), ifThenBlock ? 0 : IL_FLAGWRITE_ALL)));
		break;
    case armv5::ARMV5_SVC:
        il.AddInstruction(il.SetRegister(4, FAKEREG_SYSCALL_INFO, il.Const(4, instr->fields[instr->format->operands[0].field0])));
        il.AddInstruction(il.SystemCall());
        break;
	// Note: SXTAB, SXTAH, SXTB, SXTH, TBB, TBH are ARMv6+ only (not in ARMv5)
	case armv5::ARMV5_TEQ:
		il.AddInstruction(il.Xor(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1), IL_FLAGWRITE_CNZ));
		break;
	case armv5::ARMV5_TST:
		il.AddInstruction(il.And(4, ReadILOperand(il, instr, 0), ReadArithOperand(il, instr, 1), IL_FLAGWRITE_CNZ));
		break;
	// Note: UBFX is ARMv6T2+ only (not in ARMv5)
	case armv5::ARMV5_UDF:
		il.AddInstruction(il.Trap(instr->fields[instr->format->operands[0].field0]));
		break;
	case armv5::ARMV5_UMLAL:
	{
		uint32_t RdLo = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
		uint32_t RdHi = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
		uint32_t Rm = GetRegisterByIndex(instr->fields[instr->format->operands[2].field0]);
		uint32_t Rn = GetRegisterByIndex(instr->fields[instr->format->operands[3].field0]);

		il.AddInstruction(
			il.SetRegisterSplit(4,
				RdHi, /* hi result */
				RdLo, /* lo result */
				il.Add(8,
					il.MultDoublePrecUnsigned(4, il.Register(4, Rn), il.Register(4, Rm)),
					il.RegisterSplit(4, RdHi, RdLo)
				),
				WritesToStatus(instr, ifThenBlock) ? IL_FLAGWRITE_NZ : 0
			)
		);
		break;
	}
	case armv5::ARMV5_UMULL:
		il.AddInstruction(WriteSplitOperands(il, instr, 1, 0, il.MultDoublePrecUnsigned(4, ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3))));
		break;
	case armv5::ARMV5_SMULL:
		il.AddInstruction(WriteSplitOperands(il, instr, 1, 0, il.MultDoublePrecSigned(4, ReadILOperand(il, instr, 2), ReadILOperand(il, instr, 3))));
		break;
	case armv5::ARMV5_SMULBB:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, il.LowPart(2, ReadILOperand(il, instr, 1)),
			il.LowPart(2, ReadILOperand(il, instr, 2)), IL_FLAGWRITE_NONE)));
		break;
	case armv5::ARMV5_SMULBT:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, il.LowPart(2, ReadILOperand(il, instr, 1)),
			il.LowPart(2, il.LogicalShiftRight(4, ReadILOperand(il, instr, 2), il.Const(1, 16))), IL_FLAGWRITE_NONE)));
		break;
	case armv5::ARMV5_SMULTB:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, il.LowPart(2, il.LogicalShiftRight(4, ReadILOperand(il, instr, 1), il.Const(1, 16))),
			il.LowPart(2, ReadILOperand(il, instr, 2)), IL_FLAGWRITE_NONE)));
		break;
	case armv5::ARMV5_SMULTT:
		il.AddInstruction(WriteArithOperand(il, instr, il.Mult(4, il.LowPart(2, il.LogicalShiftRight(4, ReadILOperand(il, instr, 1), il.Const(1, 16))),
			il.LowPart(2, il.LogicalShiftRight(4, ReadILOperand(il, instr, 2), il.Const(1, 16))), IL_FLAGWRITE_NONE)));
		break;
	// Note: UXTAB, UXTAH, UXTB, UXTH are ARMv6+ only (not in ARMv5)
	// Note: WFE, WFI, RRX are ARMv6K+/ARMv7+ only (not in ARMv5)
	default:
		GetLowLevelILForNEONInstruction(arch, il, instr, ifThenBlock);
		break;
	}
	return true;
}

bool GetLowLevelILForNEONInstruction(Architecture* arch, LowLevelILFunction& il, decomp_result* instr, bool ifThenBlock)
{
	(void)arch;
	(void)ifThenBlock;
	switch (instr->mnem)
	{
	case armv5::ARMV5_VABS:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(
				WriteILOperand(il, instr, 0, il.FloatAbs(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1))));
		}
		else
		{
			// Non scalar unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv5::ARMV5_VADD:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatAdd(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		}
		else
		{
			// Non scalar unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		break;
	// Note: VBIF, VBIT, VBSL, VEOR are NEON (ARMv7+) only, not in VFPv2
	case armv5::ARMV5_VSUB:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatSub(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		}
		else
		{
			// Non scalar unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		break;
	// Note: VFMA/VFMS are VFPv4 (ARMv7+) only, not in VFPv2
	case armv5::ARMV5_VMUL:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatMult(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		}
		else
		{
			// Non scalar unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv5::ARMV5_VDIV:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(WriteArithOperand(il, instr,
				il.FloatDiv(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1), ReadILOperand(il, instr, 2))));
		}
		else
		{
			// Non scalar unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv5::ARMV5_VNEG:
		if (instr->format->operationFlags & (INSTR_FORMAT_FLAG_F32 | INSTR_FORMAT_FLAG_F64))
		{
			il.AddInstruction(
				WriteArithOperand(il, instr, il.FloatNeg(GetRegisterSize(instr, 0), ReadILOperand(il, instr, 1))));
		}
		else
		{
			// Non scalar unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		break;
	case armv5::ARMV5_VMRS:
		// TODO: If this sets the apsr register we do not track that in the core flag group.
		il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1), GetRegisterSize(instr, 1)));
		break;
	case armv5::ARMV5_VCVT:
		if (IS_FIELD_PRESENT(instr, FIELD_to_fixed))
		{
			if (IS_FIELD_PRESENT(instr, FIELD_imm))
			{
				// VCVT (between floating-point and fixed-point, Floating-point)
				/* VCVT<c>.F32.<dt> <Sd>,<Sd>,#<imm> */
				/* VCVT<c>.F64.<dt> <Dd>,<Dd>,#<imm> */
				/* VCVT<c>.<dt> <Sd>,<Sd>,#<imm> */
				/* VCVT<c>.<dt> <Dd>,<Dd>,#<imm> */
				// TODO: fixed-point unsupported.
				il.AddInstruction(il.Unimplemented());
			}
			else if (IS_FIELD_PRESENT(instr, FIELD_fbits))
			{
				// VCVT (between floating-point and fixed-point, Advanced SIMD)
				/* VCVT<c>.<dt> <Dd>,<Dm>,#<fbits> */
				/* VCVT<c>.<dt> <Qd>,<Qm>,#<fbits> */
				// TODO: vector and fixed-point unsupported.
			}
		}
		else if (IS_FIELD_PRESENT(instr, FIELD_half_to_single))
		{
			// VCVT (between half-precision and single-precision, Advanced SIMD)
			/* VCVT<c>.F16.F32 <Dd>,<Qm> */
			/* VCVT<c>.F32.F16 <Qd>,<Dm> */
			// TODO: vector and half-precision unsupported.
			il.AddInstruction(il.Unimplemented());
		}
		else if (IS_FIELD_PRESENT(instr, FIELD_double_to_single))
		{
			// VCVT (between double-precision and single-precision)
			/* VCVT<c>.F64.F32 <Dd>,<Sm> */
			/* VCVT<c>.F32.F64 <Sd>,<Dm> */
			il.AddInstruction(WriteILOperand(
				il, instr, 0, il.FloatConvert(GetRegisterSize(instr, 1), ReadILOperand(il, instr, 1))));
			break;
		}
		else if (IS_FIELD_PRESENT(instr, FIELD_to_integer))
		{
			if (IS_FIELD_PRESENT(instr, FIELD_td))
			{
				// VCVT (between floating-point and integer, Advanced SIMD)
				/* VCVT<c>.<dt> <Dd>,<Dm> */  // instr->fields[FIELD_regs] = 1
				/* VCVT<c>.<dt> <Qd>,<Qm> */  // instr->fields[FIELD_regs] = 2
				switch (instr->fields[FIELD_dt])
				{
				case VFP_DATA_SIZE_S32F32:
				case VFP_DATA_SIZE_U32F32:
					// TODO: iterate over vector components
					// break;
				case VFP_DATA_SIZE_F32S32:
				case VFP_DATA_SIZE_F32U32:
					// TODO: iterate over vector components
					// break;
				default:
					// Invalid
					il.AddInstruction(il.Unimplemented());
				}
			}
			else if (instr->fields[FIELD_to_integer])
			{
				// VCVT, VCVTR (between floating-point and integer, Floating-point)
				// TODO: handle distinction of VCVTR:
				// If R is specified, the operation uses the rounding mode specified by the FPSCR.
				// If R is omitted. the operation uses the Round towards Zero rounding mode.
				// (Note: Binary Ninja does not currently support specifying any particular rounding mode, so it doesn't matter.)
				switch (instr->fields[FIELD_dt])
				{
				case VFP_DATA_SIZE_S32F32:
				case VFP_DATA_SIZE_S32F64:
					/* VCVT<c>.S32.F32 <Sd>,<Sm> */
					/* VCVT<c>.S32.F64 <Sd>,<Dm> */
					/* VCVTR<c>.S32.F32 <Sd>,<Sm> */
					/* VCVTR<c>.S32.F64 <Sd>,<Dm> */
					il.AddInstruction(WriteILOperand(
						il, instr, 0, il.SignExtend(GetRegisterSize(instr, 0),
							il.FloatToInt(GetRegisterSize(instr, 0),
								il.RoundToInt(GetRegisterSize(instr, 0),
									ReadILOperand(il, instr, 1))))));
					break;
				case VFP_DATA_SIZE_U32F32:
				case VFP_DATA_SIZE_U32F64:
					/* VCVT<c>.U32.F32 <Sd>,<Sm> */
					/* VCVT<c>.U32.F64 <Sd>,<Dm> */
					/* VCVTR<c>.U32.F32 <Sd>,<Sm> */
					/* VCVTR<c>.U32.F64 <Sd>,<Dm> */
					il.AddInstruction(WriteILOperand(
						il, instr, 0, il.ZeroExtend(GetRegisterSize(instr, 0),
							il.FloatToInt(GetRegisterSize(instr, 0),
								il.RoundToInt(GetRegisterSize(instr, 0),
									ReadILOperand(il, instr, 1))))));
					break;
				default:
					// Invalid
					il.AddInstruction(il.Unimplemented());
				}
			}
			else
			{
				// VCVT, VCVTR (between floating-point and integer, Floating-point)
				switch (instr->fields[FIELD_dt])
				{
				case VFP_DATA_SIZE_S32:
					/* VCVT<c>.F32.<dt> <Sd>,<Sm> */
					il.AddInstruction(WriteILOperand(
						il, instr, 0, il.IntToFloat(GetRegisterSize(instr, 0),
							il.SignExtend(GetRegisterSize(instr, 0),
								ReadILOperand(il, instr, 1)))));
					break;
				case VFP_DATA_SIZE_U32:
					/* VCVT<c>.F64.<dt> <Dd>,<Sm> */
					il.AddInstruction(WriteILOperand(
						il, instr, 0, il.IntToFloat(GetRegisterSize(instr, 0),
							il.ZeroExtend(GetRegisterSize(instr, 0),
								ReadILOperand(il, instr, 1)))));
					break;
				default:
					// Invalid
					il.AddInstruction(il.Unimplemented());
				}
			}
		}
		else
			il.AddInstruction(il.Unimplemented());
		break;
	case armv5::ARMV5_VMOV:
		if (instr->format->operandCount == 4)
		{
			// s1 <- r2, s2 <- r4
			// r1 <- s0, r7 <- s1
			il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 2)));
			il.AddInstruction(WriteILOperand(il, instr, 1, ReadILOperand(il, instr, 3)));
		}
		else if (instr->format->operandCount == 3)
		{
			if (instr->format->operands[2].type == OPERAND_FORMAT_REG_FP)
			{

				uint32_t RdLo = GetRegisterByIndex(instr->fields[instr->format->operands[0].field0]);
				uint32_t RdHi = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);

				// r3:r2 <- d12
				il.AddInstruction(il.SetRegisterSplit(
					4, RdHi, RdLo, ReadILOperand(il, instr, 2, 8)));
			}
			else
			{
				uint32_t Rm = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0]);
				uint32_t Rn = GetRegisterByIndex(instr->fields[instr->format->operands[2].field0]);

				// d9 <- r1:r0
				il.AddInstruction(WriteILOperand(
					il, instr, 0, il.RegisterSplit(4, Rn, Rm), 8));
			}
		}
		else /* if (instr->format->operandCount == 2) */
		{
			if (instr->format->operands[1].type == OPERAND_FORMAT_IMM64 && strcmp(instr->format->operands[0].prefix, "q") == 0)
				// Load immediate in high and low
				il.AddInstruction(WriteILOperand(il, instr, 0,
					il.Or(16, ReadILOperand(il, instr, 1),
						il.ShiftLeft(16, ReadILOperand(il, instr, 1), il.Const(8, 64)), 16)));
			else
				// Load immediate or reg -> reg
				// r2 <= s4
				// s12 <- r8
				il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1)));
			// Note: the code below is more exlicit about the logic, but equivalent to the above:
			// if (instr->format->operands[1].type == OPERAND_FORMAT_IMM64)
			// {
			// 	if (strcmp(instr->format->operands[0].prefix, "q") == 0)
			// 		// Load immediate in high and low
			// 		il.AddInstruction(WriteILOperand(il, instr, 0,
			// 			il.Or(16, ReadILOperand(il, instr, 1),
			// 				il.ShiftLeft(16, ReadILOperand(il, instr, 1), il.Const(8, 64)), 16)));
			// 	else
			// 		// Load immediate
			// 		il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1)));
			// }
			// else
			// {
			// 	// r2 <= s4
			// 	// s12 <- r8
			// 	il.AddInstruction(WriteILOperand(il, instr, 0, ReadILOperand(il, instr, 1)));
			// }
		}
		break;
	case armv5::ARMV5_VSTM:
	{
		// TODO: Clean this code up...
		const char* prefix = "d";
		if (IS_FIELD_PRESENT(instr, FIELD_single_regs))
		{
			if (instr->fields[FIELD_single_regs] == 1)
			{
				prefix = "s";
			}
		}
		auto regSize = RegisterSizeFromPrefix(prefix);
		unsigned int d = instr->fields[FIELD_d];
		unsigned int inc = 1;
		if (IS_FIELD_PRESENT(instr, FIELD_inc))
			inc = instr->fields[FIELD_inc];
		int regs = instr->fields[FIELD_regs];
		for (int i = 0; i < regs; ++i)
		{
			if (d + (i * inc) >= 32 && strcmp(prefix, "s") == 0)
				break;
			if (i >= 16 && strcmp(prefix, "d") == 0)
				break;
			int regIdx = (d + i * inc) % 32;
			il.Store(regSize, il.Add(4, ReadILOperand(il, instr, 0), il.Const(4, i * regSize)),
				il.Register(regSize, GetRegisterByIndex(regIdx, prefix)));
		}
		break;
	}
	case armv5::ARMV5_VLDM:
	{
		// TODO: Clean this code up...
		const char* prefix = "d";
		if (IS_FIELD_PRESENT(instr, FIELD_single_regs))
		{
			if (instr->fields[FIELD_single_regs] == 1)
			{
				prefix = "s";
			}
		}
		auto regSize = RegisterSizeFromPrefix(prefix);
		unsigned int d = instr->fields[FIELD_d];
		unsigned int inc = 1;
		if (IS_FIELD_PRESENT(instr, FIELD_inc))
			inc = instr->fields[FIELD_inc];
		int regs = instr->fields[FIELD_regs];
		for (int i = 0; i < regs; ++i)
		{
			if (d + (i * inc) >= 32 && strcmp(prefix, "s") == 0)
				break;
			if (i >= 16 && strcmp(prefix, "d") == 0)
				break;
			int regIdx = (d + i * inc) % 32;
			il.AddInstruction(il.SetRegister(regSize, GetRegisterByIndex(regIdx, prefix),
				il.Load(regSize, il.Add(4, ReadILOperand(il, instr, 0), il.Const(4, i * regSize)))));
		}
		break;
	}
	case armv5::ARMV5_VPUSH:
	{
		// TODO: Clean this code up...
		const char* prefix = "d";
		if (IS_FIELD_PRESENT(instr, FIELD_single_regs))
		{
			if (instr->fields[FIELD_single_regs] == 1)
			{
				prefix = "s";
			}
		}
		auto regSize = RegisterSizeFromPrefix(prefix);
		unsigned int d = instr->fields[FIELD_d];
		unsigned int inc = 1;
		if (IS_FIELD_PRESENT(instr, FIELD_inc))
			inc = instr->fields[FIELD_inc];
		int regs = instr->fields[FIELD_regs];
		for (int i = 0; i < regs; ++i)
		{
			if (d + (i * inc) >= 32 && strcmp(prefix, "s") == 0)
				break;
			if (i >= 16 && strcmp(prefix, "d") == 0)
				break;
			int regIdx = (d + i * inc) % 32;
			il.AddInstruction(il.Push(regSize, il.Register(regSize, GetRegisterByIndex(regIdx, prefix))));
		}
		break;
	}
	case armv5::ARMV5_VPOP:
	{
		// TODO: Clean this code up...
		const char* prefix = "d";
		if (IS_FIELD_PRESENT(instr, FIELD_single_regs))
		{
			if (instr->fields[FIELD_single_regs] == 1)
			{
				prefix = "s";
			}
		}
		auto regSize = RegisterSizeFromPrefix(prefix);
		unsigned int d = instr->fields[FIELD_d];
		unsigned int inc = 1;
		if (IS_FIELD_PRESENT(instr, FIELD_inc))
			inc = instr->fields[FIELD_inc];
		int regs = instr->fields[FIELD_regs];
		for (int i = 0; i < regs; ++i)
		{
			if (d + (i * inc) >= 32 && strcmp(prefix, "s") == 0)
				break;
			if (i >= 16 && strcmp(prefix, "d") == 0)
				break;
			int regIdx = (d + i * inc) % 32;
			il.AddInstruction(il.SetRegister(regSize, GetRegisterByIndex(regIdx, prefix), il.Pop(regSize)));
		}
		break;
	}
	case armv5::ARMV5_VLDR:
	{
		uint32_t regSize = RegisterSizeFromPrefix(instr->format->operands[1].prefix);
		if (instr->format->operandCount == 3)
		{
			uint32_t reg =
				GetRegisterByIndex(instr->fields[instr->format->operands[1].field0], instr->format->operands[1].prefix);
			il.AddInstruction(
				WriteILOperand(il, instr, 0, il.Load(regSize, GetMemoryAddress(il, instr, 1, regSize, false))));
			il.AddInstruction(
				il.SetRegister(regSize, reg, il.Add(regSize, il.Register(regSize, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(WriteILOperand(il, instr, 0,
				il.Load(regSize,
					GetMemoryAddress(il, instr, 1, 4, true, 4))));
		}
		break;
	}
	case armv5::ARMV5_VSTR:
	{
		uint32_t regSize = RegisterSizeFromPrefix(instr->format->operands[1].prefix);
		if (instr->format->operandCount == 3)
		{
			uint32_t reg = GetRegisterByIndex(instr->fields[instr->format->operands[1].field0], instr->format->operands[1].prefix);
			il.AddInstruction(
				il.Store(regSize, GetMemoryAddress(il, instr, 1, regSize, false), ReadILOperand(il, instr, 0)));
			il.AddInstruction(
				il.SetRegister(regSize, reg, il.Add(regSize, il.Register(regSize, reg), ReadILOperand(il, instr, 2))));
		}
		else
		{
			il.AddInstruction(il.Store(regSize, GetMemoryAddress(il, instr, 1, regSize), ReadILOperand(il, instr, 0)));
		}
		break;
	}
	default:
		il.AddInstruction(il.Unimplemented());
		break;
	}
	return true;
}
