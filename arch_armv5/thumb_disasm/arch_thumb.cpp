#define _CRT_SECURE_NO_WARNINGS

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "binaryninjaapi.h"

// registers, etc.
#include "arch_armv5.h"
#include "spec.h"
#include "disassembler.h"
#include "il.h"

using namespace BinaryNinja;
using namespace armv5;
using namespace std;

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

static Ref<Enumeration> get_msr_op_enum()
{
	EnumerationBuilder builder;
	// ARMv5 only has CPSR and SPSR for status register access (not Cortex-M registers)
	builder.AddMemberWithValue("cpsr", REGS_CPSR);
	builder.AddMemberWithValue("cpsr_c", REGS_CPSR_C);
	builder.AddMemberWithValue("cpsr_x", REGS_CPSR_X);
	builder.AddMemberWithValue("cpsr_xc", REGS_CPSR_XC);
	builder.AddMemberWithValue("cpsr_s", REGS_CPSR_S);
	builder.AddMemberWithValue("cpsr_sc", REGS_CPSR_SC);
	builder.AddMemberWithValue("cpsr_sx", REGS_CPSR_SX);
	builder.AddMemberWithValue("cpsr_sxc", REGS_CPSR_SXC);
	builder.AddMemberWithValue("cpsr_f", REGS_CPSR_F);
	builder.AddMemberWithValue("cpsr_fc", REGS_CPSR_FC);
	builder.AddMemberWithValue("cpsr_fx", REGS_CPSR_FX);
	builder.AddMemberWithValue("cpsr_fxc", REGS_CPSR_FXC);
	builder.AddMemberWithValue("cpsr_fs", REGS_CPSR_FS);
	builder.AddMemberWithValue("cpsr_fsc", REGS_CPSR_FSC);
	builder.AddMemberWithValue("cpsr_fsx", REGS_CPSR_FSX);
	builder.AddMemberWithValue("cpsr_fsxc", REGS_CPSR_FSXC);
	builder.AddMemberWithValue("spsr", REGS_SPSR);
	builder.AddMemberWithValue("spsr_c", REGS_SPSR_C);
	builder.AddMemberWithValue("spsr_x", REGS_SPSR_X);
	builder.AddMemberWithValue("spsr_xc", REGS_SPSR_XC);
	builder.AddMemberWithValue("spsr_s", REGS_SPSR_S);
	builder.AddMemberWithValue("spsr_sc", REGS_SPSR_SC);
	builder.AddMemberWithValue("spsr_sx", REGS_SPSR_SX);
	builder.AddMemberWithValue("spsr_sxc", REGS_SPSR_SXC);
	builder.AddMemberWithValue("spsr_f", REGS_SPSR_F);
	builder.AddMemberWithValue("spsr_fc", REGS_SPSR_FC);
	builder.AddMemberWithValue("spsr_fx", REGS_SPSR_FX);
	builder.AddMemberWithValue("spsr_fxc", REGS_SPSR_FXC);
	builder.AddMemberWithValue("spsr_fs", REGS_SPSR_FS);
	builder.AddMemberWithValue("spsr_fsc", REGS_SPSR_FSC);
	builder.AddMemberWithValue("spsr_fsx", REGS_SPSR_FSX);
	builder.AddMemberWithValue("spsr_fsxc", REGS_SPSR_FSXC);
	Ref<Enumeration> _enum = builder.Finalize();
	return _enum;
}

/* class Architecture from binaryninjaapi.h */
class ThumbArchitecture: public ArmCommonArchitecture
{
protected:
	virtual std::string GetAssemblerTriple() override
	{
		if(m_endian == BigEndian)
			return "thumbv5teb-none-none";

		return "thumbv5t-none-none";
	}

	void populateDecomposeRequest(decomp_request *req, const uint8_t *data, size_t len,
		uint64_t addr, int inIfThen, int inIfThenLast)
	{
		req->instr_word16 = 0;
		req->instr_word32 = 0;
		if(m_endian == LittleEndian) {
			req->instr_word16 = *(uint16_t *)data;
			if(len >= 4) {
				req->instr_word32 = ((*(uint16_t *)data)<<16) | *(uint16_t *)(data + 2);
			}
		}
		else {
			req->instr_word16 = (data[0] << 8) | data[1];
			if(len >= 4) {
				req->instr_word32 = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
			}
		}

		req->arch = ARCH_ARMv5T;
		req->instrSet = INSTRSET_THUMB;
		req->inIfThen = inIfThen;
		req->inIfThenLast = inIfThenLast;
		req->carry_in = 0;
		req->addr = (uint32_t)addr;
	}

	virtual bool Disassemble(const uint8_t* data, uint64_t addr, size_t maxLen, decomp_result& result)
	{
		(void)addr;
		(void)maxLen;
		decomp_request request;
		populateDecomposeRequest(&request, data, maxLen, addr, IFTHEN_UNKNOWN, IFTHENLAST_UNKNOWN);

		memset(&result, 0, sizeof(result));
		if (thumb_decompose(&request, &result) != STATUS_OK)
			return false;
		return true;
	}

public:
	/* initialization list */
	ThumbArchitecture(const char* name, BNEndianness endian): ArmCommonArchitecture(name, endian)
	{
	}

	/*************************************************************************/

	virtual size_t GetMaxInstructionLength() const override
	{
		return 18; // IT blocks can have up to four following associated instructions
	}

	virtual size_t GetInstructionAlignment() const override
	{
		return 2;
	}

	virtual size_t GetOpcodeDisplayLength() const override
	{
		return 4;
	}

	/* think "GetInstructionBranchBehavior()"

	   populates struct Instruction Info (api/binaryninjaapi.h)
	   which extends struct BNInstructionInfo (core/binaryninjacore.h)

	   tasks:
		1) set the length
		2) invoke AddBranch() for every non-sequential execution possibility

	   */
	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr,
		size_t maxLen, InstructionInfo& result) override
	{
		decomp_request request;
		decomp_result decomp;

		populateDecomposeRequest(&request, data, maxLen, addr, IFTHEN_UNKNOWN, IFTHENLAST_UNKNOWN);

		if (thumb_decompose(&request, &decomp) != STATUS_OK)
			return false;
		if ((decomp.instrSize / 8) > maxLen)
			return false;
		if ((decomp.status & STATUS_UNDEFINED) || (!decomp.format))
			return false;

		result.length = decomp.instrSize / 8;

		switch (decomp.mnem)
		{
		case armv5::ARMV5_LDR:
			if ((decomp.format->operands[0].type == OPERAND_FORMAT_REG) && (decomp.fields[decomp.format->operands[0].field0] == 15))
			{
				result.AddBranch(UnresolvedBranch);
				result.archTransitionByTargetAddr = true;
			}
			break;

		case ARMV5_LDM:
		case ARMV5_LDMDA:
		case ARMV5_LDMDB:
		case ARMV5_LDMIA: // defaults to ARMV5_LDM
		case ARMV5_LDMIB:
			if ((decomp.format->operands[0].type == OPERAND_FORMAT_REG) && (decomp.fields[decomp.format->operands[0].field0] == 15))
			{
				result.AddBranch(UnresolvedBranch);
				result.archTransitionByTargetAddr = true;
			}
			break;
		// Instructions that can write to PC
		case armv5::ARMV5_ADD:
		case armv5::ARMV5_ADC:
		case armv5::ARMV5_EOR:
		case armv5::ARMV5_SUB:
		case armv5::ARMV5_SBC:
		case armv5::ARMV5_RSB:
		case armv5::ARMV5_BIC:
		case armv5::ARMV5_ORR:
		case armv5::ARMV5_LSL:
		case armv5::ARMV5_LSR:
		case armv5::ARMV5_ASR:
		case armv5::ARMV5_ROR:
		case armv5::ARMV5_MOV:
		case armv5::ARMV5_MVN:
		case armv5::ARMV5_LDRH:
		case armv5::ARMV5_LDRB:
		case armv5::ARMV5_LDRSH:
		case armv5::ARMV5_LDRSB:
		case armv5::ARMV5_ADR:
		case armv5::ARMV5_MUL:
		case armv5::ARMV5_CLZ:
			if ((decomp.format->operands[0].type == OPERAND_FORMAT_REG) && (decomp.fields[decomp.format->operands[0].field0] == 15))
				result.AddBranch(UnresolvedBranch);
			break;

		case armv5::ARMV5_B:
			if ((!(decomp.format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL)) ||
				(decomp.fields[FIELD_cond] == COND_AL)) {
				result.AddBranch(UnconditionalBranch, (decomp.fields[decomp.format->operands[0].field0] +
					4 + addr) & 0xffffffffLL, this);
			} else {
				result.AddBranch(TrueBranch, (decomp.fields[decomp.format->operands[0].field0] +
					4 + addr) & 0xffffffffLL, this);
				result.AddBranch(FalseBranch, (addr + result.length) & 0xffffffffLL, this);
			}
			break;

		case armv5::ARMV5_BX:
			if ((!(decomp.format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL)) ||
				(decomp.fields[FIELD_cond] == COND_AL)) {
				if ((decomp.format->operands[0].type == OPERAND_FORMAT_LR) ||
					((decomp.format->operands[0].type == OPERAND_FORMAT_REG) &&
						(decomp.fields[decomp.format->operands[0].field0] == 14))) {
						result.AddBranch(FunctionReturn);
						result.archTransitionByTargetAddr = true;
				} else {
					result.AddBranch(UnresolvedBranch);
					result.archTransitionByTargetAddr = true;
				}
			}
			break;

		case armv5::ARMV5_BL:
			if ((!(decomp.format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL)) ||
				(decomp.fields[FIELD_cond] == COND_AL)) {
				result.AddBranch(CallDestination, (decomp.fields[decomp.format->operands[0].field0] +
					4 + addr) & 0xffffffffLL, this);
			}
			break;

		case armv5::ARMV5_BLX:
			if ((!(decomp.format->operationFlags & INSTR_FORMAT_FLAG_CONDITIONAL)) ||
				(decomp.fields[FIELD_cond] == COND_AL)) {
				if (decomp.format->operands[0].type == OPERAND_FORMAT_IMM) {
					uint64_t target;
					if (addr & 2)
						target = (decomp.fields[decomp.format->operands[0].field0] + 2 + addr) & 0xffffffffLL;
					else
						target = (decomp.fields[decomp.format->operands[0].field0] + 4 + addr) & 0xffffffffLL;
					result.AddBranch(CallDestination, target, m_armArch);
				} else if ((decomp.format->operands[0].type == OPERAND_FORMAT_LR) ||
					((decomp.format->operands[0].type == OPERAND_FORMAT_REG) &&
						(decomp.fields[decomp.format->operands[0].field0] == 14))) {
						result.AddBranch(FunctionReturn); // initially indicate "blx lr" as a return since this is common and conservative; subsequent analysis determines if it's a function call
				}
				result.archTransitionByTargetAddr = true;
			}
			break;

		case armv5::ARMV5_POP:
			if ((decomp.format->operands[0].type == OPERAND_FORMAT_REGISTERS) &&
				(decomp.fields[FIELD_registers] & (1 << 15))) {
				result.AddBranch(FunctionReturn);
			}
			break;

		case armv5::ARMV5_SVC:
			result.AddBranch(SystemCall);
			break;

		case armv5::ARMV5_UDF:
			result.AddBranch(ExceptionBranch);
			break;

		default:
			break;
		}

		return true;
	}

	/* populate the vector result with InstructionTextToken

	*/
	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
		decomp_request request;
		decomp_result decomp;

		populateDecomposeRequest(&request, data, len, addr, IFTHEN_UNKNOWN, IFTHENLAST_UNKNOWN);

		if (thumb_decompose(&request, &decomp) != STATUS_OK)
			return false;

		if (decomp.status & STATUS_UNDEFINED) {
			len = decomp.instrSize / 8;
			result.emplace_back(InstructionToken, "undefined");
			return true;
		}

		if ((decomp.instrSize / 8) > len)
			return false;

		if (!decomp.format)
			return false;

		char padding[9];
		memset(padding, 0x20, sizeof(padding));
		string operation = get_thumb_operation_name(&decomp);
		size_t operationLen = operation.size();
		if (operationLen < 8)
		{
			padding[8-operationLen] = '\0';
		}
		else
			padding[1] = '\0';

		result.emplace_back(InstructionToken, operation);
		if (decomp.format->operandCount > 0)
			result.emplace_back(TextToken, padding);

		for (size_t i = 0; i < decomp.format->operandCount; i++)
		{
			int j;
			const instruction_operand_format& operand = decomp.format->operands[i];
			uint32_t value, r, bits, shift_t, shift_n, add, imm32, reg;
			char buf[16];
			char offset[32];
			char regname[16];
			char secondname[16];
			bool first;

			switch (operand.type)
			{
			case OPERAND_FORMAT_MEMORY_ONE_REG:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_IMM:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(value) {
					result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(TextToken, "#");

					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}

				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_NEG_IMM:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);
				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "#");

				value = decomp.fields[operand.field1];
				if (value < 10)
					snprintf(offset, sizeof(offset), "-%d", value);
				else
					snprintf(offset, sizeof(offset), "-0x%x", value);
				result.emplace_back(IntegerToken, offset, -(int64_t)value);
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_ADD_IMM:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname))
					strcpy(regname, "undefined");
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(decomp.fields[FIELD_add] && value==0) {
					/* omit the case where we are adding 0 */
					while(0);
				}
				else {
					result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(TextToken, "#");

					const char *fmt;
					if(decomp.fields[FIELD_add])
						fmt = (value < 10) ? "%d":"0x%x";
					else
						fmt = (value < 10) ? "-%d":"-0x%x";

					snprintf(offset, sizeof(offset), fmt, value);
					result.emplace_back(IntegerToken, offset, -(int64_t)value);
				}

				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if (value != 0) {
					result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(TextToken, "#");
					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_ADD_IMM:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(!(decomp.fields[FIELD_add] && value == 0)) {
					result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(TextToken, "#");
					if(decomp.fields[FIELD_add]) {
						if (value < 10)
							snprintf(offset, sizeof(offset), "%d", value);
						else
							snprintf(offset, sizeof(offset), "0x%x", value);
						result.emplace_back(IntegerToken, offset, value);
					} else {
						if (value < 10)
							snprintf(offset, sizeof(offset), "-%d", value);
						else
							snprintf(offset, sizeof(offset), "-0x%x", value);
						result.emplace_back(IntegerToken, offset, -(int64_t)value);
					}
				}
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_TWO_REG:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(0 != get_reg_name(value, secondname)) {
					strcpy(secondname, "undefined");
				}
				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, secondname);
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_TWO_REG_SHIFT:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(0 != get_reg_name(value, secondname)) {
					strcpy(secondname, "undefined");
				}
				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, secondname);

				shift_t = decomp.fields[FIELD_shift_t];
				shift_n = decomp.fields[FIELD_shift_n];

				if(shift_n != 0) {
					result.emplace_back(OperandSeparatorToken, ", ");
					if(shift_t == SRType_LSL) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "lsl #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_LSR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "lsr #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_ASR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "asr #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_RRX) {
						if(shift_n != 1) {
							snprintf(offset, sizeof(offset), "%d", shift_n);
							result.emplace_back(TextToken, "rrx #");
							result.emplace_back(IntegerToken, offset, shift_n);
						}
						else {
							result.emplace_back(TextToken, "rrx");
						}
					} else if(shift_t == SRType_ROR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "ror #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else {
						result.emplace_back(TextToken, "undefined");
					}
				}
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_ROTATION:
				value = decomp.fields[FIELD_rotation];

				if(value) {
					if(i>0)
						result.emplace_back(OperandSeparatorToken, ", ");
					result.emplace_back(TextToken, "ror #");
					snprintf(buf, sizeof(buf), "%d", value);
					result.emplace_back(IntegerToken, buf, 1);
				}

				break;

			case OPERAND_FORMAT_MEMORY_TWO_REG_LSL_ONE:
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, regname);

				value = decomp.fields[operand.field1];
				if(0 != get_reg_name(value, secondname)) {
					strcpy(secondname, "undefined");
				}
				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, secondname);
				result.emplace_back(TextToken, ", lsl #");
				result.emplace_back(IntegerToken, "1", 1);
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_SP_IMM:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, "sp");

				value = decomp.fields[operand.field0];
				if(value) {
					result.emplace_back(TextToken, ", #");

					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_SP_OPTIONAL_IMM:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, "sp");

				value = decomp.fields[operand.field0];
				if (value != 0) {
					result.emplace_back(TextToken, ", #");
					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}
				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_MEMORY_PC:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "[");
				result.emplace_back(RegisterToken, "pc");
				result.emplace_back(TextToken, "]");
				break;

			case OPERAND_FORMAT_IMM64: /* 64 bit immediate fields */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				if(IS_FIELD_PRESENT(&decomp, FIELD_imm64h) && IS_FIELD_PRESENT(&decomp, FIELD_imm64l)){
					uint64_t imm64 = 0;
					imm64 |= decomp.fields[FIELD_imm64h];
					imm64 <<= 32;
					imm64 |= decomp.fields[FIELD_imm64l];
					/* this will be '#' for lone numerals, 'p' for coprocessor, etc. */
					if (operand.prefix[0] != 0)
						result.emplace_back(TextToken, operand.prefix);

					if(imm64 < 10)
						snprintf(offset, sizeof(offset), "%" PRIu64, imm64);
					else
						snprintf(offset, sizeof(offset), "0x%" PRIx64, imm64);
					result.emplace_back(IntegerToken, offset, imm64);
				}
				/* could be closing '}' for stuff like coprocessor {<option>} in ldc */
				if (operand.suffix[0] != 0)
					result.emplace_back(TextToken, operand.suffix);
				break;

			case OPERAND_FORMAT_IMM: /* immediate fields */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				value = decomp.fields[operand.field0];

				/* this will be '#' for lone numerals, 'p' for coprocessor, etc. */
				if (operand.prefix[0] != 0)
					result.emplace_back(TextToken, operand.prefix);

				if (decomp.mnem == armv5::ARMV5_B || decomp.mnem == armv5::ARMV5_BL) {
					value += 4 + (uint32_t)addr;
					if(value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(PossibleAddressToken, offset, value);
				} else if (decomp.mnem == armv5::ARMV5_BX || decomp.mnem == armv5::ARMV5_BLX) {
					if (addr & 2)
						value += 2 + (uint32_t)addr;
					else
						value += 4 + (uint32_t)addr;
					if(value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(PossibleAddressToken, offset, value);
				} else {
					if(value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}

				/* could be closing '}' for stuff like coprocessor {<option>} in ldc */
				if (operand.suffix[0] != 0)
					result.emplace_back(TextToken, operand.suffix);

				break;

			case OPERAND_FORMAT_OPTIONAL_IMM: /* optional immediate fields */
				value = decomp.fields[operand.field0];
				if(value != 0) {
					if (i > 0)
						result.emplace_back(OperandSeparatorToken, ", ");
					if (operand.prefix[0] != 0)
						result.emplace_back(TextToken, operand.prefix);
					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				}
				break;

			case OPERAND_FORMAT_ADD_IMM: /* immediate fields */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				if (operand.prefix[0] != 0)
					result.emplace_back(TextToken, operand.prefix);

				value = decomp.fields[operand.field0];
				if(decomp.fields[FIELD_add]) {
					if (value < 10)
						snprintf(offset, sizeof(offset), "%d", value);
					else
						snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);
				} else {
					if (value < 10)
						snprintf(offset, sizeof(offset), "-%d", value);
					else
						snprintf(offset, sizeof(offset), "-0x%x", value);
					result.emplace_back(IntegerToken, offset, -(int64_t)value);
				}
				break;

			case OPERAND_FORMAT_OPTIONAL_ADD_IMM: /* optional immediate fields */
				value = decomp.fields[operand.field0];
				if(value != 0) {
					if (i > 0)
						result.emplace_back(OperandSeparatorToken, ", ");
					if (operand.prefix[0] != 0)
						result.emplace_back(TextToken, operand.prefix);
					if(decomp.fields[FIELD_add]) {
						if (value < 10)
							snprintf(offset, sizeof(offset), "%d", value);
						else
							snprintf(offset, sizeof(offset), "0x%x", value);
						result.emplace_back(IntegerToken, offset, value);
					} else {
						if (value < 10)
							snprintf(offset, sizeof(offset), "-%d", value);
						else
							snprintf(offset, sizeof(offset), "-0x%x", value);
						result.emplace_back(IntegerToken, offset, -(int64_t)value);
					}
				}
				break;

			case OPERAND_FORMAT_ZERO:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "#");
				result.emplace_back(IntegerToken, "0", 0);
				break;

			case OPERAND_FORMAT_REG: /* register fields */
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, regname);
				break;

			case OPERAND_FORMAT_REG_FP: /* floating-point regs s0..s31, d0..d31, q0..q15 */
				value = decomp.fields[operand.field0];
				if(operand.prefix[0] == 'q')
					value >>= 1;
				/* prefix should be 'd', 'q', or 'v' */
				snprintf(regname, sizeof(regname), "%s%d", operand.prefix, value);
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, regname);
				break;

			case OPERAND_FORMAT_REG_INDEX: /* floating-point regs s0..s31, d0..d31, q0..q15 */
				value = decomp.fields[operand.field0];
				if(operand.prefix[0] == 'q')
					value >>= 1;
				/* prefix should be 'd', 'q', or 'v' */
				snprintf(regname, sizeof(regname), "%s%d[%d]", operand.prefix, value, decomp.fields[operand.field1]);
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, regname);
				break;

			case OPERAND_FORMAT_FPSCR:
				switch(decomp.fields[FIELD_FPSCR]) {
					case 0:
						snprintf(regname, sizeof(regname), "fpsid");
						break;
					case 1:
						snprintf(regname, sizeof(regname), "fpscr");
						break;
					case 5:
						snprintf(regname, sizeof(regname), "mvfr2");
						break;
					case 6:
						snprintf(regname, sizeof(regname), "mvfr1");
						break;
					case 7:
						snprintf(regname, sizeof(regname), "mvfr0");
						break;
					case 8:
						snprintf(regname, sizeof(regname), "fpexc");
						break;
					case 9:
						snprintf(regname, sizeof(regname), "fpinst");
						break;
					case 10:
						snprintf(regname, sizeof(regname), "fpinst2");
						break;
					default:
						snprintf(regname, sizeof(regname), "error");
						break;
				}

				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, regname);
				break;
			case OPERAND_FORMAT_SP:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, "sp");
				break;

			case OPERAND_FORMAT_PC:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, "pc");
				break;

			case OPERAND_FORMAT_LR:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(RegisterToken, "lr");
				break;

			case OPERAND_FORMAT_COPROC: /* coproc eg: "p12" */
				value = decomp.fields[operand.field0];
				snprintf(buf, sizeof(buf), "p%d", value);
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, buf);
				break;

			case OPERAND_FORMAT_COPROC_REG: /* coproc register fields eg: "c4" */
				value = decomp.fields[operand.field0];
				snprintf(buf, sizeof(buf), "c%d", value);
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, buf);
				break;

			case OPERAND_FORMAT_LIST: /* register list */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "{");

				if(decomp.group == INSN_GROUP_NEON) {
					unsigned int n = decomp.fields[FIELD_n];

					snprintf(regname, sizeof(regname), "d%d", n);
					result.emplace_back(RegisterToken, regname);

					if(IS_FIELD_PRESENT(&decomp, FIELD_length)) {
						unsigned int inc = 1;
						if(IS_FIELD_PRESENT(&decomp, FIELD_inc))
							inc = decomp.fields[FIELD_inc];

						int length = decomp.fields[FIELD_length];

						for(int i=1; i<length; ++i) {
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "d%d", (n + i * inc) % 32);
							result.emplace_back(RegisterToken, regname);
						}
					}
				}

				result.emplace_back(TextToken, "}");
				break;
			case OPERAND_FORMAT_REGISTERS_INDEXED: /* indexed register list */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "{");

				if(decomp.group == INSN_GROUP_NEON) {
					unsigned int d = decomp.fields[FIELD_d];


					if(IS_FIELD_PRESENT(&decomp, FIELD_length)) {
						unsigned int inc = 1;
						unsigned int index = 0;
						if(IS_FIELD_PRESENT(&decomp, FIELD_inc))
							inc = decomp.fields[FIELD_inc];
						if(IS_FIELD_PRESENT(&decomp, FIELD_index))
							index = decomp.fields[FIELD_index];

						int length = decomp.fields[FIELD_length];

						snprintf(regname, sizeof(regname), "d%d[%d]", d, index);
						result.emplace_back(RegisterToken, regname);
						for(int i=1; i<length; ++i) {
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "d%d[%d]", (d + i * inc) % 32, index);
							result.emplace_back(RegisterToken, regname);
						}
					}
				}

				result.emplace_back(TextToken, "}");
				break;

			case OPERAND_FORMAT_REGISTERS: /* register list */
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "{");

				// for neon instruction, the list of registers is {1,2,3,4} long
				// and is d<Dd>[, d<Dd+1>][, d<Dd+2>][, d<Dd+3>]
				//
				// some instructions have d, d2, d3, d4
				// others just have d, but have regs
				if(decomp.group == INSN_GROUP_NEON) {
					char leader = 'd';
					if (IS_FIELD_PRESENT(&decomp, FIELD_single_regs)){
						if (decomp.fields[FIELD_single_regs] == 1) {
							leader = 's';
						}
					}
					unsigned int d = decomp.fields[FIELD_d];

					snprintf(regname, sizeof(regname), "%c%d%s", leader, d, operand.suffix);
					result.emplace_back(RegisterToken, regname);

					if(IS_FIELD_PRESENT(&decomp, FIELD_regs)) {
						unsigned int inc = 1;
						if(IS_FIELD_PRESENT(&decomp, FIELD_inc))
							inc = decomp.fields[FIELD_inc];

						int regs = decomp.fields[FIELD_regs];

						for(int i=1; i<regs; ++i) {
							if (d+(i*inc) >= 32 && leader == 's') break;
							if (i >= 16 && leader == 'd') break;
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "%c%d%s", leader, (d + i * inc) % 32, operand.suffix);
							result.emplace_back(RegisterToken, regname);
						}
					}
					else {
						int d2=-1, d3=-1, d4=-1;

						if(IS_FIELD_PRESENT(&decomp, FIELD_d2)) d2 = decomp.fields[FIELD_d2];
						if(IS_FIELD_PRESENT(&decomp, FIELD_d3)) d3 = decomp.fields[FIELD_d3];
						if(IS_FIELD_PRESENT(&decomp, FIELD_d4)) d4 = decomp.fields[FIELD_d4];

						if(d2>=0) {
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "d%d%s", decomp.fields[FIELD_d2] % 32, operand.suffix);
							result.emplace_back(RegisterToken, regname);
						}
						if(d3>=0) {
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "d%d%s", decomp.fields[FIELD_d3] % 32, operand.suffix);
							result.emplace_back(RegisterToken, regname);
						}
						if(d4>=0) {
							result.emplace_back(OperandSeparatorToken, ", ");
							snprintf(regname, sizeof(regname), "d%d%s", decomp.fields[FIELD_d4] % 32, operand.suffix);
							result.emplace_back(RegisterToken, regname);
						}
					}
				}
				else {
					r = 0;
					bits = decomp.fields[FIELD_registers];

					first = true;
					while(bits) {
						if(bits & 1) {
							if(0 != get_reg_name(r, regname)) {
								strcpy(regname, "undefined");
							}

							if (!first)
								result.emplace_back(OperandSeparatorToken, ", ");
							result.emplace_back(RegisterToken, regname);
							first = false;
						}

						r += 1;
						bits >>= 1;
					}
				}

				result.emplace_back(TextToken, "}");
				break;

			case OPERAND_FORMAT_MEMORY_ONE_REG_ALIGNED:
				if (i > 0) {
					result.emplace_back(OperandSeparatorToken, ", ");
				}

				/* get name of register */
				value = decomp.fields[operand.field0];
				if(0 != get_reg_name(value, regname)) {
					strcpy(regname, "undefined");
				}

				//printf("alignment: %d\n", decomp.fields[FIELD_alignment]);
				//printf("index_align: %d\n", decomp.fields[FIELD_index_align]);
				//printf("align: %d\n", decomp.fields[FIELD_align]);

				value = decomp.fields[FIELD_alignment];

				result.emplace_back(TextToken, "[");
				result.emplace_back(RegisterToken, regname);
				if(value != 1) {
					result.emplace_back(TextToken, ":");
					snprintf(offset, sizeof(offset), "0x%x", value);
					result.emplace_back(IntegerToken, offset, value);

				}
				result.emplace_back(TextToken, "]");

				break;

			case OPERAND_FORMAT_ENDIAN: /* endian specifier */
				if (i > 0) {
					result.emplace_back(OperandSeparatorToken, ", ");
				}

				result.emplace_back(TextToken, decomp.fields[FIELD_E] ? "be":"le");
				break;

			case OPERAND_FORMAT_SHIFT: /* "{,<shift>}" field */
				shift_t = decomp.fields[FIELD_shift_t];
				shift_n = decomp.fields[FIELD_shift_n];

				if(shift_n != 0) {
					if (i > 0)
						result.emplace_back(OperandSeparatorToken, ", ");
					if(shift_t == SRType_LSL) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "lsl #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_LSR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "lsr #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_ASR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "asr #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else if(shift_t == SRType_RRX) {
						if(shift_n != 1) {
							snprintf(offset, sizeof(offset), "%d", shift_n);
							result.emplace_back(TextToken, "rrx #");
							result.emplace_back(IntegerToken, offset, shift_n);
						}
						else {
							result.emplace_back(TextToken, "rrx");
						}
					} else if(shift_t == SRType_ROR) {
						snprintf(offset, sizeof(offset), "%d", shift_n);
						result.emplace_back(TextToken, "ror #");
						result.emplace_back(IntegerToken, offset, shift_n);
					} else {
						result.emplace_back(TextToken, "undefined");
					}
				}
				break;

			case OPERAND_FORMAT_IFLAGS:
				j = 0;
				if (decomp.fields[FIELD_A])
					buf[j++] = 'A';
				if (decomp.fields[FIELD_I])
					buf[j++] = 'I';
				if (decomp.fields[FIELD_F])
					buf[j++] = 'F';
				buf[j] = '\0';

				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				if(!j)
					result.emplace_back(TextToken, "none");
				else
					result.emplace_back(TextToken, buf);

				break;

			case OPERAND_FORMAT_BARRIER_OPTION:
				{
					// Note: Barrier instructions (ISB, DMB, DSB) are ARMv7+
					// This case shouldn't be reached for ARMv5 Thumb
					const char *lookup[16] = {"#0x0", "#0x1", "OSHST", "OSH", "#0x4",
						"#0x5", "NSHST", "NSH", "#0x8", "#0x9", "ISHST", "ISH",
						"#0xC", "#0xD", "ST", "SY"};

					uint32_t opt = decomp.fields[FIELD_barrier_option];
					if(opt <= 15)
						result.emplace_back(TextToken, lookup[opt]);
					else {
						snprintf(buf, sizeof(buf), "#0x%x", opt);
						result.emplace_back(TextToken, buf);
					}
				}
				break;

			case OPERAND_FORMAT_FIRSTCOND: /* if-then cases */
				value = decomp.fields[FIELD_firstcond];
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				if(value == 15)
					result.emplace_back(TextToken, "al");
				else
					result.emplace_back(TextToken, get_thumb_condition_name(value));
				break;

			case OPERAND_FORMAT_LABEL: /* <label> field becomes [PC,#<+/-><imm32>] */
				add = decomp.fields[FIELD_add];
				imm32 = decomp.fields[FIELD_imm32];

				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				result.emplace_back(BeginMemoryOperandToken, "[");
				result.emplace_back(RegisterToken, "pc");

				result.emplace_back(OperandSeparatorToken, ", ");
				result.emplace_back(TextToken, "#");

				if (add) {
					if (imm32 < 10)
						snprintf(offset, sizeof(offset), "%d", imm32);
					else
						snprintf(offset, sizeof(offset), "0x%x", imm32);
					result.emplace_back(IntegerToken, offset, imm32);
				} else {
					if (imm32 < 10)
						snprintf(offset, sizeof(offset), "-%d", imm32);
					else
						snprintf(offset, sizeof(offset), "-0x%x", imm32);
					result.emplace_back(IntegerToken, offset, -(int64_t)imm32);
				}

				result.emplace_back(EndMemoryOperandToken, "]");
				break;

			case OPERAND_FORMAT_RT_MRC:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				reg = decomp.fields[FIELD_Rt_mrc];
				if(reg == 15)
					result.emplace_back(RegisterToken, "apsr_nzcv");
				else {
					get_reg_name(REG_R0 + reg, regname);
					result.emplace_back(RegisterToken, regname);
				}
				break;

			case OPERAND_FORMAT_SPEC_REG:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");

				if (decomp.mnem == ARMV5_MSR) {
					uint32_t mask = decomp.fields[FIELD_mask];

					/* then this is the system level form */
					if(IS_FIELD_PRESENT(&decomp, FIELD_write_spsr)) {
						const char *c="", *x="", *s="", *f="";
						if(mask) {
							if(mask & 1) c = "c";
							if(mask & 2) x = "x";
							if(mask & 4) s = "s";
							if(mask & 8) f = "f";
						}

						/* is it SPSR write? */
						if(decomp.fields[FIELD_write_spsr]) {
							if(mask)
								snprintf(buf, sizeof(buf), "spsr_%s%s%s%s", f, s, x, c);
							else
								strcpy(buf, "spsr");
						}
						else {
							if(mask)
								snprintf(buf, sizeof(buf), "cpsr_%s%s%s%s", f, s, x, c);
							else
								strcpy(buf, "cpsr");
						}

						result.emplace_back(RegisterToken, buf);
					}
					/* application level form */
					else {
						uint32_t mask = (decomp.fields[FIELD_write_nzcvq] << 1) | decomp.fields[FIELD_write_g];
						uint8_t sysm = decomp.fields[FIELD_SYSm];
						bool xPSR = ((sysm >> 2) & 1) == 1;
						switch (sysm >> 3) {
							case 0: /* xPSR access */
							{
								string reg_name = "";
								string reg_bits = "";
								if (xPSR)
									switch (sysm & 7) {
									case 5: // '101' == IPSR
										result.emplace_back(RegisterToken, "ipsr");
										break;
									case 6: // '110' == EPSR
										result.emplace_back(RegisterToken, "epsr");
										break;
									case 7: // '111' == IEPSR
										result.emplace_back(RegisterToken, "iepsr");
										break;
									}
								else
								{
									switch (sysm & 3)
									{
									case 0:
										reg_name = "apsr";
										break;
									case 1:
										reg_name = "iapsr";
										break;
									case 2:
										reg_name = "eapsr";
										break;
									case 3:
										reg_name = "xpsr";
										break;
									}
									switch(mask) {
									case 0: // unpredictable
										break;
									case 1: // '01' == write_g
										/* aka CPSR_f */
										result.emplace_back(RegisterToken, reg_name + "_g");
										break;
									case 2:	// '10' == write_nzcvq
										/* aka CPSR_s */
										result.emplace_back(RegisterToken, reg_name + "_nzcvq");
										break;
									case 3: // '11' == write_nzcvq | write_g
										/* aka CPSR_fs */
										result.emplace_back(RegisterToken, reg_name + "_nzcvqg");
										break;
									}
								}
								break;
							}
							case 1: /* SP access */
								switch (sysm & 7) {
									case 0:
										result.emplace_back(RegisterToken, "msp");
										break;
									case 1:
										result.emplace_back(RegisterToken, "psp");
										break;
									/* default? */
								}
								break;
							case 2: /* Priority mask or CONTROL access */
								switch (sysm & 7) {
									case 0:
										result.emplace_back(RegisterToken, "primask");
										break;
									case 1:
										result.emplace_back(RegisterToken, "basepri");
										break;
									case 2:
										result.emplace_back(RegisterToken, "basepri_max");
										break;
									case 3:
										result.emplace_back(RegisterToken, "faultmask");
										break;
									case 4:
										result.emplace_back(RegisterToken, "control");
										break;
								}
								break;
							/* default? */
						}
					}
				}
				else
				if (decomp.mnem == ARMV5_MRS) {
					if (decomp.fields[FIELD_read_spsr]) {
						result.emplace_back(RegisterToken, "spsr");
					} else {
						uint8_t sysm = decomp.fields[FIELD_SYSm];
						switch (sysm >> 3) {
							case 0: /* xPSR access */
								switch (sysm & 7)
								{
								case 0:
									result.emplace_back(RegisterToken, "apsr");
									break;
								case 1:
									result.emplace_back(RegisterToken, "iapsr");
									break;
								case 2:
									result.emplace_back(RegisterToken, "eapsr");
									break;
								case 3:
									result.emplace_back(RegisterToken, "xpsr");
									break;
								case 5: // '101' == IPSR
									result.emplace_back(RegisterToken, "ipsr");
									break;
								case 6: // '110' == EPSR
									result.emplace_back(RegisterToken, "epsr");
									break;
								case 7: // '111' == IEPSR
									result.emplace_back(RegisterToken, "iepsr");
									break;
								}
								break;
							case 1: /* SP access */
								switch (sysm & 7) {
									case 0:
										result.emplace_back(RegisterToken, "msp");
										break;
									case 1:
										result.emplace_back(RegisterToken, "psp");
										break;
									/* default? */
								}
								break;
							case 2: /* Priority mask or CONTROL access */
								switch (sysm & 7) {
									case 0:
										result.emplace_back(RegisterToken, "primask");
										break;
									case 1:
									case 2:
										result.emplace_back(RegisterToken, "basepri");
										break;
									case 3:
										result.emplace_back(RegisterToken, "faultmask");
										break;
									case 4:
										result.emplace_back(RegisterToken, "control");
										break;
								}
								break;
							/* default? */
						}
					}
				}

				break;

			default:
				if (i > 0)
					result.emplace_back(OperandSeparatorToken, ", ");
				if (operand.prefix[0] != 0)
					result.emplace_back(TextToken, operand.prefix);
				if (operand.suffix[0] != 0)
					result.emplace_back(TextToken, operand.prefix);
				break;
			}

			switch (operand.writeback)
			{
			case WRITEBACK_YES:
				result.emplace_back(TextToken, "!");
				break;
			case WRITEBACK_OPTIONAL:
				if (thumb_has_writeback(&decomp))
					result.emplace_back(TextToken, "!");
				break;
			default:
				break;
			}
		}

		len = decomp.instrSize / 8;
		return true;
	}

	virtual string GetIntrinsicName(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		// ARMv5 coprocessor intrinsics
		case ARMV5_INTRIN_COPROC_GETONEWORD:
			return "Coproc_GetOneWord";
		case ARMV5_INTRIN_COPROC_GETTWOWORDS:
			return "Coproc_GetTwoWords";
		case ARMV5_INTRIN_COPROC_SENDONEWORD:
			return "Coproc_SendOneWord";
		case ARMV5_INTRIN_COPROC_SENDTWOWORDS:
			return "Coproc_SendTwoWords";
		case ARMV5_INTRIN_MRS:
			return "__mrs";
		case ARMV5_INTRIN_MSR:
			return "__msr";
		case ARMV5_INTRIN_CLZ:
			return "__clz";
		case ARMV5_INTRIN_BKPT:
			return "__bkpt";
		case ARMV5_INTRIN_PLD:
			return "__pld";
		case ARMV5_INTRIN_SWP:
			return "__swp";
		case ARMV5_INTRIN_SWPB:
			return "__swpb";
		case ARMV5_INTRIN_QADD:
			return "__qadd";
		case ARMV5_INTRIN_QSUB:
			return "__qsub";
		case ARMV5_INTRIN_QDADD:
			return "__qdadd";
		case ARMV5_INTRIN_QDSUB:
			return "__qdsub";
		default:
			return "";
		}
	}

	virtual vector<uint32_t> GetAllIntrinsics() override
	{
		return vector<uint32_t> {
			// ARMv5 intrinsics only
			ARMV5_INTRIN_COPROC_GETONEWORD,
			ARMV5_INTRIN_COPROC_GETTWOWORDS,
			ARMV5_INTRIN_COPROC_SENDONEWORD,
			ARMV5_INTRIN_COPROC_SENDTWOWORDS,
			ARMV5_INTRIN_MRS,
			ARMV5_INTRIN_MSR,
			ARMV5_INTRIN_CLZ,
			ARMV5_INTRIN_BKPT,
			ARMV5_INTRIN_PLD,
			ARMV5_INTRIN_SWP,
			ARMV5_INTRIN_SWPB,
			ARMV5_INTRIN_QADD,
			ARMV5_INTRIN_QSUB,
			ARMV5_INTRIN_QDADD,
			ARMV5_INTRIN_QDSUB,
		};
	}

	virtual vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARMV5_INTRIN_COPROC_GETONEWORD:
			return {
				NameAndType("cp", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
				NameAndType("n", Type::IntegerType(1, false)),
				NameAndType("m", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
			};
		case ARMV5_INTRIN_COPROC_GETTWOWORDS:
			return {
				NameAndType("cp", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
				NameAndType("m", Type::IntegerType(1, false)),
			};
		case ARMV5_INTRIN_COPROC_SENDONEWORD:
			return {
				NameAndType(Type::IntegerType(4, false)),
				NameAndType("cp", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
				NameAndType("n", Type::IntegerType(1, false)),
				NameAndType("m", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
			};
		case ARMV5_INTRIN_COPROC_SENDTWOWORDS:
			return {
				NameAndType(Type::IntegerType(4, false)),
				NameAndType(Type::IntegerType(4, false)),
				NameAndType("cp", Type::IntegerType(1, false)),
				NameAndType(Type::IntegerType(1, false)),
				NameAndType("m", Type::IntegerType(1, false)),
			};
		case ARMV5_INTRIN_MRS:
			// return {NameAndType(Type::IntegerType(4, false))};
			return {
				NameAndType("msr", Confidence<Ref<Type>>(Type::EnumerationType(this, get_msr_op_enum(), 4, false), BN_FULL_CONFIDENCE))
			};
		case ARMV5_INTRIN_MSR:
			// return {NameAndType(Type::IntegerType(4, false))};
			return {
				NameAndType("msr", Confidence<Ref<Type>>(Type::EnumerationType(this, get_msr_op_enum(), 4, false), BN_FULL_CONFIDENCE)),
				NameAndType(Type::IntegerType(4, false))
			};
		case ARMV5_INTRIN_DBG:
			return {NameAndType(Type::IntegerType(1, false))};
		default:
			return vector<NameAndType>();
		}
	}

	virtual vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARMV5_INTRIN_COPROC_GETONEWORD:
			return { Type::IntegerType(4, false) };
		case ARMV5_INTRIN_COPROC_GETTWOWORDS:
			return { Type::IntegerType(4, false), Type::IntegerType(4, false) };
		case ARMV5_INTRIN_MRS:
			return {Type::IntegerType(4, false)};
		case ARMV5_INTRIN_MSR:
			// return {Type::IntegerType(4, false)};
			return {};
		default:
			return vector<Confidence<Ref<Type>>>();
		}
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		decomp_request request;
		decomp_result decomp;

		// Note: ARMv5 Thumb doesn't have IT blocks (Thumb-2 / ARMv6T2+ only)
		// So we just decompose and lift each instruction directly
		populateDecomposeRequest(&request, data, len, addr, IFTHEN_NO, IFTHENLAST_NO);

		if (thumb_decompose(&request, &decomp) != STATUS_OK)
			return false;
		if ((decomp.instrSize / 8) > len)
			return false;
		if ((decomp.status & STATUS_UNDEFINED) || (!decomp.format))
			return false;

		len = decomp.instrSize / 8;
		return GetLowLevelILForThumbInstruction(this, il, &decomp);
	}

	/*************************************************************************/

	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		return false;
	}

	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		decomp_result decomp;
		if (!Disassemble(data, addr, len, decomp))
			return false;

		return (decomp.mnem == ARMV5_B && CONDITIONAL(decomp.fields[FIELD_cond]));
	}

	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		decomp_result decomp;
		if (!Disassemble(data, addr, len, decomp))
			return false;

		return (decomp.mnem == ARMV5_B && CONDITIONAL(decomp.fields[FIELD_cond]));
	}

	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		return false;
	}

	virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		return false;
	}

	/*************************************************************************/

	virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override
	{
		uint16_t nop =  0x4600;
		if (len < sizeof(nop))
			return false;
		for (size_t i = 0; i < len/sizeof(nop); i++)
			((uint16_t*)data)[i] = nop;
		return true;
	}

	virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)addr;

		if (len == sizeof(uint16_t)) {
			uint16_t *value = (uint16_t*)data;
			*value = (*value & 0x00ff) | (COND_AL << 12);
			return true;
		} else if (len == sizeof(uint32_t)) {
			uint32_t *value = (uint32_t*)data;

			uint8_t j1_bit = (*value >> 29) & 1;
			uint8_t j2_bit = (*value >> 27) & 1;
			uint8_t s_bit = (*value >> 10) & 1;
			uint8_t w = (s_bit << 3) | (s_bit << 2) | (j2_bit << 1) | (j1_bit << 0);
			*value = (*value & 0b11111111111111111111110000111111) | ((w & 0x0f) << 6);
			*value = (*value & 0b11000111111111111111111111111111) | ((0b111) << 27);

			return true;
		}

		return false;
	}

	virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)addr;
		if (len == sizeof(uint16_t)) {
			uint16_t *value = (uint16_t*)data;
			Condition cond = COND_AL;
			switch ((*value & 0x0f00) >> 8)
			{
				case COND_EQ: cond = COND_NE; break;
				case COND_NE: cond = COND_EQ; break;
				case COND_CS: cond = COND_CC; break;
				case COND_CC: cond = COND_CS; break;
				case COND_MI: cond = COND_PL; break;
				case COND_PL: cond = COND_MI; break;
				case COND_VS: cond = COND_VC; break;
				case COND_VC: cond = COND_VS; break;
				case COND_HI: cond = COND_LS; break;
				case COND_LS: cond = COND_HI; break;
				case COND_GE: cond = COND_LT; break;
				case COND_LT: cond = COND_GE; break;
				case COND_GT: cond = COND_LE; break;
				case COND_LE: cond = COND_GT; break;
			}
			*value = (*value & 0xf0ff) | (cond << 8);
			return true;
		} else if (len == sizeof(uint32_t)) {
			uint32_t *value = (uint32_t*)data;
			Condition cond = COND_AL;
			switch ((*value & 0b0000000000000000001111000000) >> 6)
			{
				case COND_EQ: cond = COND_NE; break;
				case COND_NE: cond = COND_EQ; break;
				case COND_CS: cond = COND_CC; break;
				case COND_CC: cond = COND_CS; break;
				case COND_MI: cond = COND_PL; break;
				case COND_PL: cond = COND_MI; break;
				case COND_VS: cond = COND_VC; break;
				case COND_VC: cond = COND_VS; break;
				case COND_HI: cond = COND_LS; break;
				case COND_LS: cond = COND_HI; break;
				case COND_GE: cond = COND_LT; break;
				case COND_LT: cond = COND_GE; break;
				case COND_GT: cond = COND_LE; break;
				case COND_LE: cond = COND_GT; break;
			}
			*value = (*value & 0b11111111111111111111110000111111) | (cond << 6) ;
			return true;
		}
		return false;
	}

	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override
	{
		(void)data;
		(void)addr;
		(void)len;
		(void)value;
		return false;
	}

	/*************************************************************************/

	virtual std::vector<uint32_t> GetSystemRegisters() override
	{
		return vector<uint32_t>{
			// ARMv5 system registers
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
			// VFPv2 system registers
			REGS_FPSID,
			REGS_FPSCR,
			REGS_FPEXC,
		};
	}
};

ArmCommonArchitecture* InitThumbArchitecture(const char* name, BNEndianness endian)
{
	return new ThumbArchitecture(name, endian);
}
