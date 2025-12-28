
#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include "spec.h" /* FIELD_imm8, FIELD_MAX, etc. */
#include "disassembler.h" /* decomp_request, decomp_result */

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wparentheses-equality"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wparentheses-equality"
#endif

/* forward declarations */
int adc_register(struct decomp_request *req, struct decomp_result *res);
int add_immediate(struct decomp_request *req, struct decomp_result *res);
int add_register(struct decomp_request *req, struct decomp_result *res);
int add_sp_plus_immediate(struct decomp_request *req, struct decomp_result *res);
int adr(struct decomp_request *req, struct decomp_result *res);
int and_register(struct decomp_request *req, struct decomp_result *res);
int asr_immediate(struct decomp_request *req, struct decomp_result *res);
int asr_register(struct decomp_request *req, struct decomp_result *res);
int b(struct decomp_request *req, struct decomp_result *res);
int bic_register(struct decomp_request *req, struct decomp_result *res);
int bkpt(struct decomp_request *req, struct decomp_result *res);
int bl(struct decomp_request *req, struct decomp_result *res);
int bl_blx_prefix(struct decomp_request *req, struct decomp_result *res);
int blx(struct decomp_request *req, struct decomp_result *res);
int blx_imm(struct decomp_request *req, struct decomp_result *res);
int bx(struct decomp_request *req, struct decomp_result *res);
int cmn_register(struct decomp_request *req, struct decomp_result *res);
int cmp_immediate(struct decomp_request *req, struct decomp_result *res);
int cmp_register(struct decomp_request *req, struct decomp_result *res);
int cond_branch_superv_call(struct decomp_request *req, struct decomp_result *res);
int data_proc(struct decomp_request *req, struct decomp_result *res);
int eor_register(struct decomp_request *req, struct decomp_result *res);
int ldm(struct decomp_request *req, struct decomp_result *res);
int ldr_immediate(struct decomp_request *req, struct decomp_result *res);
int ldr_register(struct decomp_request *req, struct decomp_result *res);
int ldrb_immediate(struct decomp_request *req, struct decomp_result *res);
int ldrb_register(struct decomp_request *req, struct decomp_result *res);
int ldrh_immediate(struct decomp_request *req, struct decomp_result *res);
int ldrh_register(struct decomp_request *req, struct decomp_result *res);
int ldrsb_register(struct decomp_request *req, struct decomp_result *res);
int ldrsh_register(struct decomp_request *req, struct decomp_result *res);
int load_lit_pool(struct decomp_request *req, struct decomp_result *res);
int load_store_single_data(struct decomp_request *req, struct decomp_result *res);
int lsl_immediate(struct decomp_request *req, struct decomp_result *res);
int lsl_register(struct decomp_request *req, struct decomp_result *res);
int lsr_immediate(struct decomp_request *req, struct decomp_result *res);
int lsr_register(struct decomp_request *req, struct decomp_result *res);
int misc(struct decomp_request *req, struct decomp_result *res);
int mov_immediate(struct decomp_request *req, struct decomp_result *res);
int mov_register(struct decomp_request *req, struct decomp_result *res);
int mul_register(struct decomp_request *req, struct decomp_result *res);
int mvn_register(struct decomp_request *req, struct decomp_result *res);
int orr_register(struct decomp_request *req, struct decomp_result *res);
int pop(struct decomp_request *req, struct decomp_result *res);
int push(struct decomp_request *req, struct decomp_result *res);
int ror_register(struct decomp_request *req, struct decomp_result *res);
int rsb_immediate(struct decomp_request *req, struct decomp_result *res);
int sbc_register(struct decomp_request *req, struct decomp_result *res);
int shift_immediate_add_sub_mov_cmp(struct decomp_request *req, struct decomp_result *res);
int spcl_data_branch_exch(struct decomp_request *req, struct decomp_result *res);
int stm(struct decomp_request *req, struct decomp_result *res);
int str_immediate(struct decomp_request *req, struct decomp_result *res);
int str_register(struct decomp_request *req, struct decomp_result *res);
int strb_immediate(struct decomp_request *req, struct decomp_result *res);
int strb_register(struct decomp_request *req, struct decomp_result *res);
int strh_immediate(struct decomp_request *req, struct decomp_result *res);
int strh_register(struct decomp_request *req, struct decomp_result *res);
int sub_immediate(struct decomp_request *req, struct decomp_result *res);
int sub_register(struct decomp_request *req, struct decomp_result *res);
int sub_sp_minus_immediate(struct decomp_request *req, struct decomp_result *res);
int svc(struct decomp_request *req, struct decomp_result *res);
int thumb16(struct decomp_request *req, struct decomp_result *res);
int thumb_root(struct decomp_request *req, struct decomp_result *res);
int tst_register(struct decomp_request *req, struct decomp_result *res);
int udf(struct decomp_request *req, struct decomp_result *res);
int undefined(struct decomp_request *req, struct decomp_result *res);
int undefined32(struct decomp_request *req, struct decomp_result *res);
int unpredictable(struct decomp_request *req, struct decomp_result *res);

// see A8.4.3
int DecodeImmShift_shift_t(uint8_t enc_bits, uint8_t imm5)
{
	if(enc_bits == 0)
		return SRType_LSL;
	else if(enc_bits == 1)
		return SRType_LSR;
	else if(enc_bits == 2)
		return SRType_ASR;
	else if(enc_bits == 3) {
		if(imm5 == 0)
			return SRType_RRX;
		else
			return SRType_ROR;
	}
	return SRType_ERROR;
}

int DecodeImmShift_shift_n(uint8_t enc_bits, uint8_t imm5)
{
	if(enc_bits == 0)
		return imm5;
	else if(enc_bits == 1)
		return imm5 ? imm5 : 32;
	else if(enc_bits == 2)
		return imm5 ? imm5 : 32;
	else if(enc_bits == 3) {
		if(imm5 == 0)
			return 1;
		else
			return imm5;
	}
	return -1;
}

int BadReg(uint8_t reg)
{
	return (reg==13) || (reg==15);
}

uint64_t Replicate(uint32_t rep, uint32_t before, char before_char, uint32_t after, char after_char, uint8_t times) {
    uint64_t imm64 = 0;
    uint32_t i, time;
    for (time = 0; time < times; time++) {
        if (time > 0) {
            for (i = 0; i < before+8; i++) {
                imm64 <<= 1;
                imm64 |= before_char;
            }
        }
        imm64 |= rep;
        for (i = 0; i < after; i++) {
            imm64 <<= 1;
            imm64 |= after_char;
        }
    }
    return imm64;
}

uint32_t VFPExpandImm(uint32_t imm, uint32_t N, uint32_t lowbits) {

    uint32_t E = 0;
    if (N == 32) {
        E = 8;
    }
    else {
        E = 11;
    }
    uint32_t F = (N - E) - 1;
    uint32_t sign = (imm >> 7) & 1;
    uint32_t exp = ((imm >> 6) & 1) ^ 1;
    for (uint32_t i = 0; i < E-3; i++) {
        exp <<= 1;
        exp |= (imm >> 6) & 1;
    }
    exp <<= 2;
    exp |= (imm >> 4) & 3;
    uint32_t frac = (imm & 15);
    frac <<= F-4;
    uint32_t out = (sign << 31) | (exp << 23) | (frac);

    return out;
}

uint32_t AdvSIMDExpandImm(uint32_t op, uint32_t cmode, uint32_t imm8, uint32_t lowbits) {

    uint32_t testimm8;
    uint64_t imm64 = 0;
    uint32_t imm32 = 0;
    uint32_t i = 0;
    imm8 = imm8 & 0xff;
    switch(cmode >> 1) {
        case 0:
            testimm8 = 0;
            imm64 = Replicate(imm8, 24, 0, 0, 0, 2);
            if (lowbits) return imm64 & 0xffffffff;
            return 0;
            break;
        case 1:
            testimm8 = 1;
            imm64 = Replicate(imm8, 16, 0, 8, 0, 2);
            if (lowbits) return imm64 & 0xffffffff;
            return 0;
            break;
        case 2:
            testimm8 = 1;
            imm64 = Replicate(imm8, 8, 0, 16, 0, 2);
            if (lowbits) return imm64 & 0xffffffff;
            return 0;
            break;
        case 3:
            testimm8 = 1;
            imm64 = Replicate(imm8, 0, 0, 24, 0, 2);
            if (lowbits) return imm64 & 0xffffffff;
            return 0;
            break;
        case 4:
            testimm8 = 0;
            imm64 = Replicate(imm8, 8, 0, 0, 0, 4);
            if (lowbits) return imm64 & 0xff;
            return 0;
            break;
        case 5:
            testimm8 = 1;
            imm64 = Replicate(imm8, 0, 0, 8, 0, 4);
            if (lowbits) return imm64 & 0xffff;
            return 0;
            break;
        case 6:
            testimm8 = 1;
            if ((cmode & 1) == 0) {
                imm64 = Replicate(imm8, 16, 0, 8, 1, 2);
            }
            else {
                imm64 = Replicate(imm8, 8, 0, 16, 1, 2);
            }
            if (lowbits) return imm64 & 0xffffffff;
            return 0;
            break;
        case 7:
            testimm8 = 0;
            if ((cmode & 1) == 0 && (op & 1) == 0) {
                imm64 = Replicate(imm8, 0, 0, 0, 0, 8);
                if (lowbits) return imm8;
                return 0;
            }

            else if ((cmode & 1) == 0 && (op & 1) == 1) {
                int i, j;
                for (i = 0; i < 8; i++) {
                    for (j = 0; j < 8; j++) {
                        imm64 |= ((imm8 >> (7-i)) & 1);
                        if (i != 7 || j != 7) imm64 <<= 1;
                    }
                }
            }
            else if ((cmode & 1) == 1 && (op & 1) == 0) {
                imm32 = ((imm8 >> 7) & 1);
                imm32 <<= 1;
                imm32 |= ((imm8 >> 6) & 1) ? 0 : 1;
                for (i = 0; i < 5; i++) {
                    imm32 <<= 1;
                    imm32 |= (imm8 >> 6) & 1;
                }
                imm32 <<= 6;
                imm32 |= (imm8 & 63);
                imm32 <<= 19;
                imm64 = imm32;
            }
            else if ((cmode & 1) == 1 && (op & 1) == 1) {
                //return undefined()
            }
            break;
    }

    if (testimm8 && imm8 == 0) {
        //return undefined()
    }

    if (lowbits) return imm64 & 0xffffffff;
    return imm64 >> 32;
}

uint32_t ROR_C(uint32_t input, int shamt)
{
	shamt %= 32;
	uint32_t left = input << (32-shamt);
	uint32_t right = input >> shamt;
	return left | right;
}

uint32_t ROR_C_cout(uint32_t input, int shamt)
{
	return ROR_C(input, shamt) >> 31;
}

int ThumbExpandImm_C_imm32(uint32_t imm12, uint32_t carry_in)
{
	(void)carry_in;

	if(0 == (imm12 & 0xC00)) {
		uint32_t idx = (imm12 & 0x300)>>8;
		uint32_t tmp = imm12 & 0xFF;
		if(idx==0) {
			return tmp;
		}
		else if(idx==1) {
			return (tmp << 16) | tmp;
		}
		else if(idx==2) {
			return (tmp << 24) | (tmp << 8);
		}
		else {
			return (tmp << 24) | (tmp << 16) | (tmp << 8) | tmp;
		}
	}
	else {
		uint32_t value = 0x80 | (imm12 & 0x7F);
		uint32_t rotamt = (imm12 & 0xF80) >> 7;
		return ROR_C(value, rotamt);
	}
}

int ThumbExpandImm_C_cout(uint32_t imm12, uint32_t carry_in)
{
	if(0 == (imm12 & 0xC00)) {
		return carry_in;
	}
	else {
		uint32_t unrot_value = 0x80 | (imm12 & 0x7F);
		return ROR_C_cout(unrot_value, (imm12 & 0xF80) >> 7);
	}
}

// TODO: replace with optimized implementation
int BitCount(int x)
{
	int answer = 0;
	while(x) {
		if(x&1) answer += 1;
		x>>=1;
	}
	return answer;
}

uint32_t SignExtend(uint32_t val, int inWidth)
{
	int doExtend = val & (1 << (inWidth-1));

	if(doExtend) {
		uint32_t mask = (uint32_t)-1 ^ ((1<<inWidth)-1);
		val = mask | val;
	}

	return val;
}

void printBits(uint32_t val, int bit_width, int str_width)
{
	int left_pad = (str_width > bit_width) ? str_width - bit_width : 0;
	for(int i=0; i<left_pad; ++i) printf(" ");

	if(bit_width > 32) bit_width = 32;
	for(int i=bit_width-1; i>=0; --i)
		printf("%c", (val & (1<<i)) ? '1' : '0');
}

#if defined(__APPLE__) || defined(__MACH__)
int __attribute__((optnone)) success(void) {
	/* debugger script can break here to see path taken */
	return 0;
}
#else
int success(void) {
	return 0;
}
#endif

// gen_crc: 3A2B228E
int adc_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,0101,Rm.3,Rdn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4140)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* ADCS <Rdn>,<Rm> */
					"adcs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* ADC<c> <Rdn>,<Rm> */
					"adc", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_ADCS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 97EEBDEC
int add_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="000,11,1,0,imm3.3,Rn.3,Rd.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x1C00)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm3] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_imm3 >> 6] |= 1LL << (FIELD_imm3 & 63);
			char imm3_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* ADDS <Rd>,<Rn>,#<imm3> */
					"adds", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm3,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
				{ /* ADD<c> <Rd>,<Rn>,#<imm3> */
					"add", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm3,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_ADDS;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: imm32 = ZeroExtend(imm3, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm3];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* Encoding T2 */
	/* pattern="001,10,Rdn.3,imm8.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x3000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rdn] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* ADDS <Rdn>,#<imm8> */
					"adds", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* ADD<c> <Rdn>,#<imm8> */
					"add", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_ADDS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: imm32 = ZeroExtend(imm8, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm8];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: C6EF7190
int add_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="000,11,0,0,Rm.3,Rn.3,Rd.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x1800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* ADDS <Rd>,<Rn>,<Rm> */
					"adds", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
				{ /* ADD<c> <Rd>,<Rn>,<Rm> */
					"add", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_ADDS;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* Encoding T2 */
	/* pattern="010001,00,DN.1,Rm.4,Rdn.3" width=16 stringency=9 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFF00)==0x4400)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_DN] = (instr & 0x80)>>7;
			res->fields_mask[FIELD_DN >> 6] |= 1LL << (FIELD_DN & 63);
			char DN_width = 1;
			res->fields[FIELD_Rm] = (instr & 0x78)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 4;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* ADD<c> <Rdn>,<Rm> */
					"add", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_ADD;

			/* pcode: Rdn = UInt(DN:Rdn) */
			res->fields[FIELD_Rdn] = ((res->fields[FIELD_DN]<<Rdn_width)|(res->fields[FIELD_Rdn]));
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			/* pcode: d = UInt(DN:Rdn) */
			res->fields[FIELD_d] = ((res->fields[FIELD_DN]<<Rdn_width)|(res->fields[FIELD_Rdn]));
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = d */
			res->fields[FIELD_n] = res->fields[FIELD_d];
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = FALSE */
			res->fields[FIELD_setflags] = 0;
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);
			/* pcode: if d < 8 && m < 8 then UNPREDICTABLE */
			if(((res->fields[FIELD_d]) < (8)) && ((res->fields[FIELD_m]) < (8))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			/* pcode: if n == 15 && m == 15 then UNPREDICTABLE */
			if(((res->fields[FIELD_n]) == (15)) && ((res->fields[FIELD_m]) == (15))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			/* pcode: if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE */
			if((((res->fields[FIELD_d]) == (15)) && (req->inIfThen == IFTHEN_YES)) && (!(req->inIfThenLast == IFTHENLAST_YES))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 55B90354
int add_sp_plus_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1010,1,Rd.3,imm8.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0xA800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rd] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* ADD<c> <Rd>,SP,#<imm32> */
					"add", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_SP,FIELD_UNINIT,FIELD_UNINIT,"sp","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm32,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_ADD;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: setflags = FALSE */
			res->fields[FIELD_setflags] = 0;
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: imm32 = ZeroExtend(imm8:'00', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm8]<<2)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* Encoding T2 */
	/* pattern="1011,0000,0,imm7.7" width=16 stringency=9 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFF80)==0xB000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm7] = instr & 0x7F;
			res->fields_mask[FIELD_imm7 >> 6] |= 1LL << (FIELD_imm7 & 63);
			char imm7_width = 7;

			static const instruction_format instr_formats[] =
			{
				{ /* ADD<c> SP,#<imm32> */
					"add", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_SP,FIELD_UNINIT,FIELD_UNINIT,"sp","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm32,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_ADD;

			/* pcode: d = 13 */
			res->fields[FIELD_d] = 13;
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: setflags = FALSE */
			res->fields[FIELD_setflags] = 0;
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: imm32 = ZeroExtend(imm7:'00', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm7]<<2)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 3084F1C6
int adr(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1010,0,Rd.3,imm8.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0xA000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rd] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* ADR<c> <Rd>,#<imm32> */
					"adr", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm32,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_ADR;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: imm32 = ZeroExtend(imm8:'00', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm8]<<2)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 832FBEA6
int and_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,0000,Rm.3,Rdn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* ANDS <Rdn>,<Rm> */
					"ands", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* AND<c> <Rdn>,<Rm> */
					"and", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_ANDS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 35C87547
int asr_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="000,10,imm5.5,Rm.3,Rd.3" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x1000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm5] = (instr & 0x7C0)>>6;
			res->fields_mask[FIELD_imm5 >> 6] |= 1LL << (FIELD_imm5 & 63);
			char imm5_width = 5;
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* ASRS <Rd>,<Rm>,#<shift_n> */
					"asrs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_shift_n,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
				{ /* ASR<c> <Rd>,<Rm>,#<shift_n> */
					"asr", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_shift_n,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_ASRS;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (-, shift_n) = DecodeImmShift('10', imm5) */
			res->fields[FIELD_shift_n] = DecodeImmShift_shift_n(0x2, res->fields[FIELD_imm5]);
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: E4E49B4F
int asr_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,0100,Rm.3,Rdn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4100)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* ASRS <Rdn>,<Rm> */
					"asrs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* ASR<c> <Rdn>,<Rm> */
					"asr", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_ASRS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: B8D93482
int b(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1101,cond.4,imm8.8" width=16 stringency=4 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF000)==0xD000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = (instr & 0xF00)>>8;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			char cond_width = 4;
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* B<c> #<imm32> */
					"b", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_IMM,FIELD_imm32,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_B;

			/* pcode: if cond == '1110' then UNDEFINED */
			if((res->fields[FIELD_cond]) == (0xE)) {
				res->status |= STATUS_UNDEFINED;
			}
			/* pcode: if cond == '1111' then SEE SVC */
			if((res->fields[FIELD_cond]) == (0xF)) {

				return svc(req, res);
			}
			/* pcode: imm32 = SignExtend(imm8:'0', 32) */
			res->fields[FIELD_imm32] = SignExtend((res->fields[FIELD_imm8]<<1)|(0x0),1+8);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: if InITBlock() then UNPREDICTABLE */
			if(req->inIfThen == IFTHEN_YES) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* Encoding T2 */
	/* pattern="11100,imm11.11" width=16 stringency=9 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0xE000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm11] = instr & 0x7FF;
			res->fields_mask[FIELD_imm11 >> 6] |= 1LL << (FIELD_imm11 & 63);
			char imm11_width = 11;

			static const instruction_format instr_formats[] =
			{
				{ /* B<c> #<imm32> */
					"b", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_IMM,FIELD_imm32,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_B;

			/* pcode: imm32 = SignExtend(imm11:'0', 32) */
			res->fields[FIELD_imm32] = SignExtend((res->fields[FIELD_imm11]<<1)|(0x0),1+11);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: if InITBlock() && !LastInITBlock() then UNPREDICTABLE */
			if((req->inIfThen == IFTHEN_YES) && (!(req->inIfThenLast == IFTHENLAST_YES))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 684F2374
int bic_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,1110,Rm.3,Rdn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4380)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* BICS <Rdn>,<Rm> */
					"bics", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* BIC<c> <Rdn>,<Rm> */
					"bic", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_BICS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 664A645A
int bkpt(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1011,1110,imm8.8" width=16 stringency=8 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFF00)==0xBE00)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* BKPT #<imm8> */
					"bkpt", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_BKPT;

			/* pcode: imm32 = ZeroExtend(imm8, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm8];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: B0C86D0B
int bl(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="11110,S.1,imm10.10,11,J1.1,1,J2.1,imm11.11" width=32 stringency=20 */
	{
		uint32_t instr = req->instr_word32;
		if(((instr & 0xF800D000)==0xF000D000)) {
			res->instrSize = 32;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_S] = (instr & 0x4000000)>>26;
			res->fields_mask[FIELD_S >> 6] |= 1LL << (FIELD_S & 63);
			char S_width = 1;
			res->fields[FIELD_imm10] = (instr & 0x3FF0000)>>16;
			res->fields_mask[FIELD_imm10 >> 6] |= 1LL << (FIELD_imm10 & 63);
			char imm10_width = 10;
			res->fields[FIELD_J1] = (instr & 0x2000)>>13;
			res->fields_mask[FIELD_J1 >> 6] |= 1LL << (FIELD_J1 & 63);
			char J1_width = 1;
			res->fields[FIELD_J2] = (instr & 0x800)>>11;
			res->fields_mask[FIELD_J2 >> 6] |= 1LL << (FIELD_J2 & 63);
			char J2_width = 1;
			res->fields[FIELD_imm11] = instr & 0x7FF;
			res->fields_mask[FIELD_imm11 >> 6] |= 1LL << (FIELD_imm11 & 63);
			char imm11_width = 11;

			static const instruction_format instr_formats[] =
			{
				{ /* BL<c> #<imm32> */
					"bl", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_IMM,FIELD_imm32,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_BL;

			/* pcode: I1 = NOT(J1 EOR S) */
			res->fields[FIELD_I1] = (~((res->fields[FIELD_J1]) ^ (res->fields[FIELD_S])) & 1);
			res->fields_mask[FIELD_I1 >> 6] |= 1LL << (FIELD_I1 & 63);
			/* pcode: I2 = NOT(J2 EOR S) */
			res->fields[FIELD_I2] = (~((res->fields[FIELD_J2]) ^ (res->fields[FIELD_S])) & 1);
			res->fields_mask[FIELD_I2 >> 6] |= 1LL << (FIELD_I2 & 63);
			/* pcode: imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32) */
			res->fields[FIELD_imm32] = SignExtend((res->fields[FIELD_S]<<(1+11+10+2+1))|(res->fields[FIELD_I1]<<(1+11+10+2))|(res->fields[FIELD_I2]<<(1+11+10))|(res->fields[FIELD_imm10]<<(1+11))|(res->fields[FIELD_imm11]<<1)|(0x0),1+11+10+2+1+S_width);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: toARM = FALSE */
			res->fields[FIELD_toARM] = 0;
			res->fields_mask[FIELD_toARM >> 6] |= 1LL << (FIELD_toARM & 63);
			/* pcode: if InITBlock() && !LastInITBlock() then UNPREDICTABLE */
			if((req->inIfThen == IFTHEN_YES) && (!(req->inIfThenLast == IFTHENLAST_YES))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: CBCF3304
int bl_blx_prefix(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	uint32_t instr = req->instr_word32;
	uint32_t xx = (instr & 0x7FF8000)>>15;
	uint32_t op = (instr & 0x6000)>>13;
	uint32_t x = instr & 0x1FFF;
	if(((op & 0x3)==0x3)) return bl(req, res);
	if(((op & 0x3)==0x2)) return blx_imm(req, res);
	if(1) return undefined32(req, res);
	return undefined(req, res);
}

// gen_crc: 7382B915
int blx(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010001,11,1,Rm.4,(0)(0)(0)" width=16 stringency=12 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFF80)==0x4780)) {
			res->instrSize = 16;
			if(!((instr & 0x7)==0x0)) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			if(!(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x78)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 4;

			static const instruction_format instr_formats[] =
			{
				{ /* BLX<c> <Rm> */
					"blx", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_BLX;

			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: if m == 15 then UNPREDICTABLE */
			if((res->fields[FIELD_m]) == (15)) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			/* pcode: if InITBlock() && !LastInITBlock() then UNPREDICTABLE */
			if((req->inIfThen == IFTHEN_YES) && (!(req->inIfThenLast == IFTHENLAST_YES))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: FE2A982D
int blx_imm(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="11110,S.1,imm10H.10,11,J1.1,0,J2.1,imm10L.10,H.1" width=32 stringency=21 */
	{
		uint32_t instr = req->instr_word32;
		if(((instr & 0xF800D000)==0xF000C000)) {
			res->instrSize = 32;
			if(!(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_S] = (instr & 0x4000000)>>26;
			res->fields_mask[FIELD_S >> 6] |= 1LL << (FIELD_S & 63);
			char S_width = 1;
			res->fields[FIELD_imm10H] = (instr & 0x3FF0000)>>16;
			res->fields_mask[FIELD_imm10H >> 6] |= 1LL << (FIELD_imm10H & 63);
			char imm10H_width = 10;
			res->fields[FIELD_J1] = (instr & 0x2000)>>13;
			res->fields_mask[FIELD_J1 >> 6] |= 1LL << (FIELD_J1 & 63);
			char J1_width = 1;
			res->fields[FIELD_J2] = (instr & 0x800)>>11;
			res->fields_mask[FIELD_J2 >> 6] |= 1LL << (FIELD_J2 & 63);
			char J2_width = 1;
			res->fields[FIELD_imm10L] = (instr & 0x7FE)>>1;
			res->fields_mask[FIELD_imm10L >> 6] |= 1LL << (FIELD_imm10L & 63);
			char imm10L_width = 10;
			res->fields[FIELD_H] = instr & 0x1;
			res->fields_mask[FIELD_H >> 6] |= 1LL << (FIELD_H & 63);
			char H_width = 1;

			static const instruction_format instr_formats[] =
			{
				{ /* BLX<c> #<imm32> */
					"blx", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_IMM,FIELD_imm32,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_BLX;

			/* pcode: I1 = NOT(J1 EOR S) */
			res->fields[FIELD_I1] = (~((res->fields[FIELD_J1]) ^ (res->fields[FIELD_S])) & 1);
			res->fields_mask[FIELD_I1 >> 6] |= 1LL << (FIELD_I1 & 63);
			/* pcode: I2 = NOT(J2 EOR S) */
			res->fields[FIELD_I2] = (~((res->fields[FIELD_J2]) ^ (res->fields[FIELD_S])) & 1);
			res->fields_mask[FIELD_I2 >> 6] |= 1LL << (FIELD_I2 & 63);
			/* pcode: imm32 = SignExtend(S:I1:I2:imm10H:imm10L:H:'0', 32) */
			res->fields[FIELD_imm32] = SignExtend((res->fields[FIELD_S]<<(1+H_width+imm10L_width+imm10H_width+2+1))|(res->fields[FIELD_I1]<<(1+H_width+imm10L_width+imm10H_width+2))|(res->fields[FIELD_I2]<<(1+H_width+imm10L_width+imm10H_width))|(res->fields[FIELD_imm10H]<<(1+H_width+imm10L_width))|(res->fields[FIELD_imm10L]<<(1+H_width))|(res->fields[FIELD_H]<<1)|(0x0),1+H_width+imm10L_width+imm10H_width+2+1+S_width);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: toARM = TRUE */
			res->fields[FIELD_toARM] = 1;
			res->fields_mask[FIELD_toARM >> 6] |= 1LL << (FIELD_toARM & 63);
			/* pcode: if InITBlock() && !LastInITBlock() then UNPREDICTABLE */
			if((req->inIfThen == IFTHEN_YES) && (!(req->inIfThenLast == IFTHENLAST_YES))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 7A24C8EC
int bx(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010001,11,0,Rm.4,(0)(0)(0)" width=16 stringency=12 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFF80)==0x4700)) {
			res->instrSize = 16;
			if(!((instr & 0x7)==0x0)) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x78)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 4;

			static const instruction_format instr_formats[] =
			{
				{ /* BX<c> <Rm> */
					"bx", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_BX;

			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: if InITBlock() && !LastInITBlock() then UNPREDICTABLE */
			if((req->inIfThen == IFTHEN_YES) && (!(req->inIfThenLast == IFTHENLAST_YES))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 3FC1BB79
int cmn_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,1011,Rm.3,Rn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x42C0)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = instr & 0x7;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* CMN<c> <Rn>,<Rm> */
					"cmn", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_CMN;

			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 22CF5872
int cmp_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="001,01,Rn.3,imm8.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x2800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rn] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* CMP<c> <Rn>,#<imm8> */
					"cmp", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_CMP;

			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: imm32 = ZeroExtend(imm8, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm8];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 8336D90A
int cmp_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,1010,Rm.3,Rn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4280)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = instr & 0x7;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* CMP<c> <Rn>,<Rm> */
					"cmp", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_CMP;

			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* Encoding T2 */
	/* pattern="010001,01,N.1,Rm.4,Rn.3" width=16 stringency=9 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFF00)==0x4500)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_N] = (instr & 0x80)>>7;
			res->fields_mask[FIELD_N >> 6] |= 1LL << (FIELD_N & 63);
			char N_width = 1;
			res->fields[FIELD_Rm] = (instr & 0x78)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 4;
			res->fields[FIELD_Rn] = instr & 0x7;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* CMP<c> <Rn>,<Rm> */
					"cmp", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_CMP;

			/* pcode: n = UInt(N:Rn) */
			res->fields[FIELD_n] = ((res->fields[FIELD_N]<<Rn_width)|(res->fields[FIELD_Rn]));
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);
			/* pcode: if n < 8 && m < 8 then UNPREDICTABLE */
			if(((res->fields[FIELD_n]) < (8)) && ((res->fields[FIELD_m]) < (8))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			/* pcode: if n == 15 || m == 15 then UNPREDICTABLE */
			if(((res->fields[FIELD_n]) == (15)) || ((res->fields[FIELD_m]) == (15))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			/* pcode: Rn = UInt(N:Rn) */
			res->fields[FIELD_Rn] = ((res->fields[FIELD_N]<<Rn_width)|(res->fields[FIELD_Rn]));
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: C9675F31
int cond_branch_superv_call(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	uint16_t instr = req->instr_word16;
	uint16_t Opcode = (instr & 0xF00)>>8;
	if(((Opcode & 0xF)==0xE)) return udf(req, res);
	if(((Opcode & 0xF)==0xF)) return svc(req, res);
	if(!((Opcode & 0xE)==0xE)) return b(req, res);
	return undefined(req, res);
}

// gen_crc: E8AB6A7C
int data_proc(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	uint16_t instr = req->instr_word16;
	uint16_t Opcode = (instr & 0x3C0)>>6;
	if(((Opcode & 0xF)==0x0)) return and_register(req, res);
	if(((Opcode & 0xF)==0x1)) return eor_register(req, res);
	if(((Opcode & 0xF)==0x2)) return lsl_register(req, res);
	if(((Opcode & 0xF)==0x3)) return lsr_register(req, res);
	if(((Opcode & 0xF)==0x4)) return asr_register(req, res);
	if(((Opcode & 0xF)==0x5)) return adc_register(req, res);
	if(((Opcode & 0xF)==0x6)) return sbc_register(req, res);
	if(((Opcode & 0xF)==0x7)) return ror_register(req, res);
	if(((Opcode & 0xF)==0x8)) return tst_register(req, res);
	if(((Opcode & 0xF)==0x9)) return rsb_immediate(req, res);
	if(((Opcode & 0xF)==0xA)) return cmp_register(req, res);
	if(((Opcode & 0xF)==0xB)) return cmn_register(req, res);
	if(((Opcode & 0xF)==0xC)) return orr_register(req, res);
	if(((Opcode & 0xF)==0xD)) return mul_register(req, res);
	if(((Opcode & 0xF)==0xE)) return bic_register(req, res);
	if(((Opcode & 0xF)==0xF)) return mvn_register(req, res);
	return undefined(req, res);
}

// gen_crc: 4E1A3CF1
int eor_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,0001,Rm.3,Rdn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4040)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* EORS <Rdn>,<Rm> */
					"eors", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* EOR<c> <Rdn>,<Rm> */
					"eor", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_EORS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: CF8304B4
int ldm(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1100,1,Rn.3,register_list.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0xC800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rn] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_register_list] = instr & 0xFF;
			res->fields_mask[FIELD_register_list >> 6] |= 1LL << (FIELD_register_list & 63);
			char register_list_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* LDM<c> <Rn>!,<registers> */
					"ldm", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_YES},
						{OPERAND_FORMAT_REGISTERS,FIELD_registers,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* LDM<c> <Rn>,<registers> */
					"ldm", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REGISTERS,FIELD_registers,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_LDM;

			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: registers = '00000000':register_list */
			res->fields[FIELD_registers] = (0x0<<register_list_width)|(res->fields[FIELD_register_list]);
			res->fields_mask[FIELD_registers >> 6] |= 1LL << (FIELD_registers & 63);
			/* pcode: wback = (registers<n> == '0') */
			res->fields[FIELD_wback] = (((res->fields[FIELD_registers] & (1<<res->fields[FIELD_n])) >> res->fields[FIELD_n]) == (0x0));
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);
			/* pcode: if BitCount(registers) < 1 then UNPREDICTABLE */
			if((BitCount(res->fields[FIELD_registers])) < (1)) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 609F58C0
int ldr_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0110,1,imm5.5,Rn.3,Rt.3" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x6800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm5] = (instr & 0x7C0)>>6;
			res->fields_mask[FIELD_imm5 >> 6] |= 1LL << (FIELD_imm5 & 63);
			char imm5_width = 5;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LDR<c> <Rt>,[<Rn>{,#<imm32>}] */
					"ldr", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM,FIELD_Rn,FIELD_imm32,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_LDR;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: imm32 = ZeroExtend(imm5:'00', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm5]<<2)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* Encoding T2 */
	/* pattern="1001,1,Rt.3,imm8.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x9800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rt] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* LDR<c> <Rt>,[SP{,#<imm32>}] */
					"ldr", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_SP_OPTIONAL_IMM,FIELD_imm32,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_LDR;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = 13 */
			res->fields[FIELD_n] = 13;
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: imm32 = ZeroExtend(imm8:'00', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm8]<<2)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: AA76A11F
int ldr_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0101,100,Rm.3,Rn.3,Rt.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x5800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LDR<c> <Rt>,[<Rn>,<Rm>] */
					"ldr", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_TWO_REG,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_LDR;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: D9BE5099
int ldrb_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0111,1,imm5.5,Rn.3,Rt.3" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x7800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm5] = (instr & 0x7C0)>>6;
			res->fields_mask[FIELD_imm5 >> 6] |= 1LL << (FIELD_imm5 & 63);
			char imm5_width = 5;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LDRB<c> <Rt>,[<Rn>{,#<imm5>}] */
					"ldrb", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM,FIELD_Rn,FIELD_imm5,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_LDRB;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: imm32 = ZeroExtend(imm5, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm5];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 86583167
int ldrb_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0101,110,Rm.3,Rn.3,Rt.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x5C00)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LDRB<c> <Rt>,[<Rn>,<Rm>] */
					"ldrb", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_TWO_REG,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_LDRB;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 065252DD
int ldrh_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1000,1,imm5.5,Rn.3,Rt.3" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x8800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm5] = (instr & 0x7C0)>>6;
			res->fields_mask[FIELD_imm5 >> 6] |= 1LL << (FIELD_imm5 & 63);
			char imm5_width = 5;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LDRH<c> <Rt>,[<Rn>{,#<imm32>}] */
					"ldrh", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM,FIELD_Rn,FIELD_imm32,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_LDRH;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: imm32 = ZeroExtend(imm5:'0', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm5]<<1)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 9ADF0A02
int ldrh_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0101,101,Rm.3,Rn.3,Rt.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x5A00)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LDRH<c> <Rt>,[<Rn>,<Rm>] */
					"ldrh", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_TWO_REG,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_LDRH;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: B2BD6A7C
int ldrsb_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0101,011,Rm.3,Rn.3,Rt.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x5600)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LDRSB<c> <Rt>,[<Rn>,<Rm>] */
					"ldrsb", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_TWO_REG,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_LDRSB;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: B1261B83
int ldrsh_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0101,111,Rm.3,Rn.3,Rt.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x5E00)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LDRSH<c> <Rt>,[<Rn>,<Rm>] */
					"ldrsh", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_TWO_REG,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_LDRSH;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: F6B5461F
int load_lit_pool(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="01001,Rt.3,imm8.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x4800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rt] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* LDR<c> <Rt>,<label> */
					"ldr", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_LABEL,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_LDR;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: imm32 = ZeroExtend(imm8:'00', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm8]<<2)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: Rt = UInt(Rt) */
			res->fields[FIELD_Rt] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 96C7DBD3
int load_store_single_data(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	uint16_t instr = req->instr_word16;
	uint16_t opA = (instr & 0xF000)>>12;
	uint16_t opB = (instr & 0xE00)>>9;
	if(((opA & 0xF)==0x5) && ((opB & 0x7)==0x0)) return str_register(req, res);
	if(((opA & 0xF)==0x5) && ((opB & 0x7)==0x1)) return strh_register(req, res);
	if(((opA & 0xF)==0x5) && ((opB & 0x7)==0x2)) return strb_register(req, res);
	if(((opA & 0xF)==0x5) && ((opB & 0x7)==0x3)) return ldrsb_register(req, res);
	if(((opA & 0xF)==0x5) && ((opB & 0x7)==0x4)) return ldr_register(req, res);
	if(((opA & 0xF)==0x5) && ((opB & 0x7)==0x5)) return ldrh_register(req, res);
	if(((opA & 0xF)==0x5) && ((opB & 0x7)==0x6)) return ldrb_register(req, res);
	if(((opA & 0xF)==0x5) && ((opB & 0x7)==0x7)) return ldrsh_register(req, res);
	if(((opA & 0xF)==0x6) && ((opB & 0x4)==0x0)) return str_immediate(req, res);
	if(((opA & 0xF)==0x6) && ((opB & 0x4)==0x4)) return ldr_immediate(req, res);
	if(((opA & 0xF)==0x7) && ((opB & 0x4)==0x0)) return strb_immediate(req, res);
	if(((opA & 0xF)==0x7) && ((opB & 0x4)==0x4)) return ldrb_immediate(req, res);
	if(((opA & 0xF)==0x8) && ((opB & 0x4)==0x0)) return strh_immediate(req, res);
	if(((opA & 0xF)==0x8) && ((opB & 0x4)==0x4)) return ldrh_immediate(req, res);
	if(((opA & 0xF)==0x9) && ((opB & 0x4)==0x0)) return str_immediate(req, res);
	if(((opA & 0xF)==0x9) && ((opB & 0x4)==0x4)) return ldr_immediate(req, res);
	return undefined(req, res);
}

// gen_crc: FEBC06DA
int lsl_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="000,00,imm5.5,Rm.3,Rd.3" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x0)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm5] = (instr & 0x7C0)>>6;
			res->fields_mask[FIELD_imm5 >> 6] |= 1LL << (FIELD_imm5 & 63);
			char imm5_width = 5;
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LSLS <Rd>,<Rm>,#<shift_n> */
					"lsls", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_shift_n,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
				{ /* LSL<c> <Rd>,<Rm>,#<shift_n> */
					"lsl", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_shift_n,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_LSLS;

			/* pcode: if imm5 == '00000' then SEE MOV (register) */
			if((res->fields[FIELD_imm5]) == (0x0)) {

				return mov_register(req, res);
			}
			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (-, shift_n) = DecodeImmShift('00', imm5) */
			res->fields[FIELD_shift_n] = DecodeImmShift_shift_n(0x0, res->fields[FIELD_imm5]);
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: BFBBE7F7
int lsl_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,0010,Rm.3,Rdn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4080)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LSLS <Rdn>,<Rm> */
					"lsls", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* LSL<c> <Rdn>,<Rm> */
					"lsl", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_LSLS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: BBCB12DE
int lsr_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="000,01,imm5.5,Rm.3,Rd.3" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm5] = (instr & 0x7C0)>>6;
			res->fields_mask[FIELD_imm5 >> 6] |= 1LL << (FIELD_imm5 & 63);
			char imm5_width = 5;
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LSRS <Rd>,<Rm>,#<shift_n> */
					"lsrs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_shift_n,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
				{ /* LSR<c> <Rd>,<Rm>,#<shift_n> */
					"lsr", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_shift_n,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_LSRS;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (-, shift_n) = DecodeImmShift('01', imm5) */
			res->fields[FIELD_shift_n] = DecodeImmShift_shift_n(0x1, res->fields[FIELD_imm5]);
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 38F0B02A
int lsr_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,0011,Rm.3,Rdn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x40C0)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* LSRS <Rdn>,<Rm> */
					"lsrs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* LSR<c> <Rdn>,<Rm> */
					"lsr", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_LSRS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 8E84B1D5
int misc(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	uint16_t instr = req->instr_word16;
	uint16_t opcode = (instr & 0xFE0)>>5;
	if(((opcode & 0x7C)==0x0)) return add_sp_plus_immediate(req, res);
	if(((opcode & 0x7C)==0x4)) return sub_sp_minus_immediate(req, res);
	if(((opcode & 0x78)==0x70)) return bkpt(req, res);
	if(((opcode & 0x70)==0x20)) return push(req, res);
	if(((opcode & 0x70)==0x60)) return pop(req, res);
	if(1) return undefined(req, res);
	return undefined(req, res);
}

// gen_crc: 08624BCE
int mov_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="001,00,Rd.3,imm8.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x2000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rd] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* MOVS <Rd>,#<imm8> */
					"movs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* MOV<c> <Rd>,#<imm8> */
					"mov", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_MOVS;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: imm32 = ZeroExtend(imm8, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm8];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: carry = APSR.C */
			res->fields[FIELD_carry] = res->fields[FIELD_APSR_C];
			res->fields_mask[FIELD_carry >> 6] |= 1LL << (FIELD_carry & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 19C88607
int mov_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010001,10,D.1,Rm.4,Rd.3" width=16 stringency=9 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFF00)==0x4600)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_D] = (instr & 0x80)>>7;
			res->fields_mask[FIELD_D >> 6] |= 1LL << (FIELD_D & 63);
			char D_width = 1;
			res->fields[FIELD_Rm] = (instr & 0x78)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 4;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* MOV<c> <Rd>,<Rm> */
					"mov", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_MOV;

			/* pcode: d = UInt(D:Rd) */
			res->fields[FIELD_d] = ((res->fields[FIELD_D]<<Rd_width)|(res->fields[FIELD_Rd]));
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = FALSE */
			res->fields[FIELD_setflags] = 0;
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: if d < 8 && m < 8 then UNPREDICTABLE */
			if(((res->fields[FIELD_d]) < (8)) && ((res->fields[FIELD_m]) < (8))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			/* pcode: if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE */
			if((((res->fields[FIELD_d]) == (15)) && (req->inIfThen == IFTHEN_YES)) && (!(req->inIfThenLast == IFTHENLAST_YES))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* Encoding T2 */
	/* pattern="000,00,00000,Rm.3,Rd.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x0)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* MOVS <Rd>,<Rm> */
					"movs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_MOVS;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = TRUE */
			res->fields[FIELD_setflags] = 1;
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: if InITBlock() then UNPREDICTABLE */
			if(req->inIfThen == IFTHEN_YES) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 003854C7
int mul_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,1101,Rn.3,Rdm.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4340)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rdm] = instr & 0x7;
			res->fields_mask[FIELD_Rdm >> 6] |= 1LL << (FIELD_Rdm & 63);
			char Rdm_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* MULS <Rdm>,<Rn>,<Rdm> */
					"muls", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rdm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
				{ /* MUL<c> <Rdm>,<Rn>,<Rdm> */
					"mul", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rdm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_MULS;

			/* pcode: d = UInt(Rdm) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdm]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rdm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rdm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: if ArchVersion() < 6 && d == n then UNPREDICTABLE */
			if(((req->arch) < (6)) && ((res->fields[FIELD_d]) == (res->fields[FIELD_n]))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: BEEAF3A6
int mvn_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,1111,Rm.3,Rd.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x43C0)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* MVNS <Rd>,<Rm> */
					"mvns", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* MVN<c> <Rd>,<Rm> */
					"mvn", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_MVNS;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: B5CAED87
int orr_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,1100,Rm.3,Rdn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4300)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* ORRS <Rdn>,<Rm> */
					"orrs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* ORR<c> <Rdn>,<Rm> */
					"orr", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_ORRS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: FF66AD83
int pop(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1011,110,P.1,register_list.8" width=16 stringency=8 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0xBC00)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_P] = (instr & 0x100)>>8;
			res->fields_mask[FIELD_P >> 6] |= 1LL << (FIELD_P & 63);
			char P_width = 1;
			res->fields[FIELD_register_list] = instr & 0xFF;
			res->fields_mask[FIELD_register_list >> 6] |= 1LL << (FIELD_register_list & 63);
			char register_list_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* POP<c> <registers> */
					"pop", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REGISTERS,FIELD_registers,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_POP;

			/* pcode: registers = P:'0000000':register_list */
			res->fields[FIELD_registers] = (res->fields[FIELD_P]<<(7+register_list_width))|(0x0<<register_list_width)|(res->fields[FIELD_register_list]);
			res->fields_mask[FIELD_registers >> 6] |= 1LL << (FIELD_registers & 63);
			/* pcode: UnalignedAllowed = FALSE */
			res->fields[FIELD_UnalignedAllowed] = 0;
			res->fields_mask[FIELD_UnalignedAllowed >> 6] |= 1LL << (FIELD_UnalignedAllowed & 63);
			/* pcode: if BitCount(registers) < 1 then UNPREDICTABLE */
			if((BitCount(res->fields[FIELD_registers])) < (1)) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			/* pcode: if registers<15> == '1' && InITBlock() && !LastInITBlock() then UNPREDICTABLE */
			if(((((res->fields[FIELD_registers] & (1<<15)) >> 15) == (0x1)) && (req->inIfThen == IFTHEN_YES)) && (!(req->inIfThenLast == IFTHENLAST_YES))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 1D0CB8FB
int push(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1011,010,M.1,register_list.8" width=16 stringency=8 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0xB400)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_M] = (instr & 0x100)>>8;
			res->fields_mask[FIELD_M >> 6] |= 1LL << (FIELD_M & 63);
			char M_width = 1;
			res->fields[FIELD_register_list] = instr & 0xFF;
			res->fields_mask[FIELD_register_list >> 6] |= 1LL << (FIELD_register_list & 63);
			char register_list_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* PUSH<c> <registers> */
					"push", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REGISTERS,FIELD_registers,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_PUSH;

			/* pcode: registers = '0':M:'000000':register_list */
			res->fields[FIELD_registers] = (0x0<<(6+register_list_width+M_width))|(res->fields[FIELD_M]<<(6+register_list_width))|(0x0<<register_list_width)|(res->fields[FIELD_register_list]);
			res->fields_mask[FIELD_registers >> 6] |= 1LL << (FIELD_registers & 63);
			/* pcode: UnalignedAllowed = FALSE */
			res->fields[FIELD_UnalignedAllowed] = 0;
			res->fields_mask[FIELD_UnalignedAllowed >> 6] |= 1LL << (FIELD_UnalignedAllowed & 63);
			/* pcode: if BitCount(registers) < 1 then UNPREDICTABLE */
			if((BitCount(res->fields[FIELD_registers])) < (1)) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 7813853A
int ror_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,0111,Rm.3,Rdn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x41C0)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* RORS <Rdn>,<Rm> */
					"rors", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* ROR<c> <Rdn>,<Rm> */
					"ror", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_RORS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 5880D851
int rsb_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,1001,Rn.3,Rd.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4240)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* RSBS <Rd>,<Rn>,#0 */
					"rsbs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_ZERO,FIELD_UNINIT,FIELD_UNINIT,"#0","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
				{ /* RSB<c> <Rd>,<Rn>,#0 */
					"rsb", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_ZERO,FIELD_UNINIT,FIELD_UNINIT,"#0","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_RSBS;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: imm32 = Zeros(32) */
			res->fields[FIELD_imm32] = /* 32-bit */ 0;
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: A236F1BB
int sbc_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,0110,Rm.3,Rdn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4180)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rdn] = instr & 0x7;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* SBCS <Rdn>,<Rm> */
					"sbcs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* SBC<c> <Rdn>,<Rm> */
					"sbc", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_SBCS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: F29F6C78
int shift_immediate_add_sub_mov_cmp(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	uint16_t instr = req->instr_word16;
	uint16_t Opcode = (instr & 0x3E00)>>9;
	uint16_t clue = (instr & 0x1C0)>>6;
	if(((Opcode & 0x1F)==0x0) && ((clue & 0x7)==0x0)) return mov_register(req, res);
	if(((Opcode & 0x1F)==0xC) && 1) return add_register(req, res);
	if(((Opcode & 0x1F)==0xD) && 1) return sub_register(req, res);
	if(((Opcode & 0x1F)==0xE) && 1) return add_immediate(req, res);
	if(((Opcode & 0x1F)==0xF) && 1) return sub_immediate(req, res);
	if(((Opcode & 0x1C)==0x0) && 1) return lsl_immediate(req, res);
	if(((Opcode & 0x1C)==0x4) && 1) return lsr_immediate(req, res);
	if(((Opcode & 0x1C)==0x8) && 1) return asr_immediate(req, res);
	if(((Opcode & 0x1C)==0x10) && 1) return mov_immediate(req, res);
	if(((Opcode & 0x1C)==0x14) && 1) return cmp_immediate(req, res);
	if(((Opcode & 0x1C)==0x18) && 1) return add_immediate(req, res);
	if(((Opcode & 0x1C)==0x1C) && 1) return sub_immediate(req, res);
	return undefined(req, res);
}

// gen_crc: 950140FC
int spcl_data_branch_exch(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	uint16_t instr = req->instr_word16;
	uint16_t Opcode = (instr & 0x3C0)>>6;
	if(((Opcode & 0xF)==0x0)) return add_register(req, res);
	if(((Opcode & 0xF)==0x1)) return add_register(req, res);
	if(((Opcode & 0xF)==0x4)) return cmp_register(req, res);
	if(((Opcode & 0xF)==0x5)) return cmp_register(req, res);
	if(((Opcode & 0xF)==0x8)) return mov_register(req, res);
	if(((Opcode & 0xF)==0x9)) return mov_register(req, res);
	if(((Opcode & 0xE)==0x2)) return add_register(req, res);
	if(((Opcode & 0xE)==0x6)) return cmp_register(req, res);
	if(((Opcode & 0xE)==0xA)) return mov_register(req, res);
	if(((Opcode & 0xE)==0xC)) return bx(req, res);
	if(((Opcode & 0xE)==0xE)) return blx(req, res);
	return undefined(req, res);
}

// gen_crc: C5393AE7
int stm(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1100,0,Rn.3,register_list.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0xC000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rn] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_register_list] = instr & 0xFF;
			res->fields_mask[FIELD_register_list >> 6] |= 1LL << (FIELD_register_list & 63);
			char register_list_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* STM<c> <Rn>!,<registers> */
					"stm", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_YES},
						{OPERAND_FORMAT_REGISTERS,FIELD_registers,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_STM;

			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: registers = '00000000':register_list */
			res->fields[FIELD_registers] = (0x0<<register_list_width)|(res->fields[FIELD_register_list]);
			res->fields_mask[FIELD_registers >> 6] |= 1LL << (FIELD_registers & 63);
			/* pcode: wback = TRUE */
			res->fields[FIELD_wback] = 1;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);
			/* pcode: if BitCount(registers) < 1 then UNPREDICTABLE */
			if((BitCount(res->fields[FIELD_registers])) < (1)) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 43EEC831
int str_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0110,0,imm5.5,Rn.3,Rt.3" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x6000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm5] = (instr & 0x7C0)>>6;
			res->fields_mask[FIELD_imm5 >> 6] |= 1LL << (FIELD_imm5 & 63);
			char imm5_width = 5;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* STR<c> <Rt>,[<Rn>{,#<imm32>}] */
					"str", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM,FIELD_Rn,FIELD_imm32,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_STR;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: imm32 = ZeroExtend(imm5:'00', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm5]<<2)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* Encoding T2 */
	/* pattern="1001,0,Rt.3,imm8.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x9000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rt] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* STR<c> <Rt>,[SP{,#<imm32>}] */
					"str", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_SP_OPTIONAL_IMM,FIELD_imm32,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_STR;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = 13 */
			res->fields[FIELD_n] = 13;
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: imm32 = ZeroExtend(imm8:'00', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm8]<<2)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: D88B83B8
int str_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0101,000,Rm.3,Rn.3,Rt.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x5000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* STR<c> <Rt>,[<Rn>,<Rm>] */
					"str", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_TWO_REG,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_STR;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 70995CF3
int strb_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0111,0,imm5.5,Rn.3,Rt.3" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x7000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm5] = (instr & 0x7C0)>>6;
			res->fields_mask[FIELD_imm5 >> 6] |= 1LL << (FIELD_imm5 & 63);
			char imm5_width = 5;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* STRB<c> <Rt>,[<Rn>{,#<imm5>}] */
					"strb", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM,FIELD_Rn,FIELD_imm5,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_STRB;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: imm32 = ZeroExtend(imm5, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm5];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: B0610D2E
int strb_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0101,010,Rm.3,Rn.3,Rt.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x5400)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* STRB<c> <Rt>,[<Rn>,<Rm>] */
					"strb", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_TWO_REG,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_STRB;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 7077127A
int strh_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1000,0,imm5.5,Rn.3,Rt.3" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x8000)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm5] = (instr & 0x7C0)>>6;
			res->fields_mask[FIELD_imm5 >> 6] |= 1LL << (FIELD_imm5 & 63);
			char imm5_width = 5;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* STRH<c> <Rt>,[<Rn>{,#<imm32>}] */
					"strh", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM,FIELD_Rn,FIELD_imm32,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_STRH;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: imm32 = ZeroExtend(imm5:'0', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm5]<<1)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: ACE6364B
int strh_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="0101,001,Rm.3,Rn.3,Rt.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x5200)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rt] = instr & 0x7;
			res->fields_mask[FIELD_Rt >> 6] |= 1LL << (FIELD_Rt & 63);
			char Rt_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* STRH<c> <Rt>,[<Rn>,<Rm>] */
					"strh", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rt,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_MEMORY_TWO_REG,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_STRH;

			/* pcode: t = UInt(Rt) */
			res->fields[FIELD_t] = (res->fields[FIELD_Rt]);
			res->fields_mask[FIELD_t >> 6] |= 1LL << (FIELD_t & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: index = TRUE */
			res->fields[FIELD_index] = 1;
			res->fields_mask[FIELD_index >> 6] |= 1LL << (FIELD_index & 63);
			/* pcode: add = TRUE */
			res->fields[FIELD_add] = 1;
			res->fields_mask[FIELD_add >> 6] |= 1LL << (FIELD_add & 63);
			/* pcode: wback = FALSE */
			res->fields[FIELD_wback] = 0;
			res->fields_mask[FIELD_wback >> 6] |= 1LL << (FIELD_wback & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 21CA4D8D
int sub_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="000,11,1,1,imm3.3,Rn.3,Rd.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x1E00)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm3] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_imm3 >> 6] |= 1LL << (FIELD_imm3 & 63);
			char imm3_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* SUBS <Rd>,<Rn>,#<imm3> */
					"subs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm3,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
				{ /* SUB<c> <Rd>,<Rn>,#<imm3> */
					"sub", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm3,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_SUBS;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: imm32 = ZeroExtend(imm3, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm3];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* Encoding T2 */
	/* pattern="001,11,Rdn.3,imm8.8" width=16 stringency=5 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xF800)==0x3800)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rdn] = (instr & 0x700)>>8;
			res->fields_mask[FIELD_Rdn >> 6] |= 1LL << (FIELD_Rdn & 63);
			char Rdn_width = 3;
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* SUBS <Rdn>,#<imm8> */
					"subs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
				{ /* SUB<c> <Rdn>,#<imm8> */
					"sub", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rdn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_SUBS;

			/* pcode: d = UInt(Rdn) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rdn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rdn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: imm32 = ZeroExtend(imm8, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm8];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 17B16220
int sub_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="000,11,0,1,Rm.3,Rn.3,Rd.3" width=16 stringency=7 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFE00)==0x1A00)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x1C0)>>6;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;
			res->fields[FIELD_Rd] = instr & 0x7;
			res->fields_mask[FIELD_Rd >> 6] |= 1LL << (FIELD_Rd & 63);
			char Rd_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* SUBS <Rd>,<Rn>,<Rm> */
					"subs", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
				{ /* SUB<c> <Rd>,<Rn>,<Rm> */
					"sub", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rd,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					3 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 2;
			res->mnem = armv5::ARMV5_SUBS;

			/* pcode: d = UInt(Rd) */
			res->fields[FIELD_d] = (res->fields[FIELD_Rd]);
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: setflags = !InITBlock() */
			res->fields[FIELD_setflags] = !(req->inIfThen == IFTHEN_YES);
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 82262A9B
int sub_sp_minus_immediate(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1011,0000,1,imm7.7" width=16 stringency=9 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFF80)==0xB080)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm7] = instr & 0x7F;
			res->fields_mask[FIELD_imm7 >> 6] |= 1LL << (FIELD_imm7 & 63);
			char imm7_width = 7;

			static const instruction_format instr_formats[] =
			{
				{ /* SUB<c> SP,#<imm32> */
					"sub", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_SP,FIELD_UNINIT,FIELD_UNINIT,"sp","",WRITEBACK_NO},
						{OPERAND_FORMAT_IMM,FIELD_imm32,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_SUB;

			/* pcode: d = 13 */
			res->fields[FIELD_d] = 13;
			res->fields_mask[FIELD_d >> 6] |= 1LL << (FIELD_d & 63);
			/* pcode: setflags = FALSE */
			res->fields[FIELD_setflags] = 0;
			res->fields_mask[FIELD_setflags >> 6] |= 1LL << (FIELD_setflags & 63);
			/* pcode: imm32 = ZeroExtend(imm7:'00', 32) */
			res->fields[FIELD_imm32] = (res->fields[FIELD_imm7]<<2)|(0x0);
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 6919EF5D
int svc(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1101,1111,imm8.8" width=16 stringency=8 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFF00)==0xDF00)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* SVC<c> #<imm8> */
					"svc", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_SVC;

			/* pcode: imm32 = ZeroExtend(imm8, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm8];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);
			/* pcode: if InITBlock() && !LastInITBlock() then UNPREDICTABLE */
			if((req->inIfThen == IFTHEN_YES) && (!(req->inIfThenLast == IFTHENLAST_YES))) {
				res->flags |= FLAG_UNPREDICTABLE;
			}

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 3251FBC4
int thumb16(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	uint16_t instr = req->instr_word16;
	uint16_t Opcode = (instr & 0xFC00)>>10;
	if(((Opcode & 0x3F)==0x10)) return data_proc(req, res);
	if(((Opcode & 0x3F)==0x11)) return spcl_data_branch_exch(req, res);
	if(((Opcode & 0x3E)==0x12)) return load_lit_pool(req, res);
	if(((Opcode & 0x3E)==0x28)) return adr(req, res);
	if(((Opcode & 0x3E)==0x2A)) return add_sp_plus_immediate(req, res);
	if(((Opcode & 0x3E)==0x30)) return stm(req, res);
	if(((Opcode & 0x3E)==0x32)) return ldm(req, res);
	if(((Opcode & 0x3E)==0x38)) return b(req, res);
	if(((Opcode & 0x3C)==0x14)) return load_store_single_data(req, res);
	if(((Opcode & 0x3C)==0x2C)) return misc(req, res);
	if(((Opcode & 0x3C)==0x34)) return cond_branch_superv_call(req, res);
	if(((Opcode & 0x38)==0x18)) return load_store_single_data(req, res);
	if(((Opcode & 0x38)==0x20)) return load_store_single_data(req, res);
	if(((Opcode & 0x30)==0x0)) return shift_immediate_add_sub_mov_cmp(req, res);
	return undefined(req, res);
}

// gen_crc: D5C4060B
int thumb_root(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	uint16_t instr = req->instr_word16;
	uint16_t tmp = (instr & 0xF800)>>11;
	if(((tmp & 0x1F)==0x1E)) return bl_blx_prefix(req, res);
	if(((tmp & 0x1F)==0x1D)) return undefined32(req, res);
	if(((tmp & 0x1F)==0x1F)) return undefined32(req, res);
	if(1) return thumb16(req, res);
	return undefined(req, res);
}

// gen_crc: 231344B4
int tst_register(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="010000,1000,Rm.3,Rn.3" width=16 stringency=10 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFFC0)==0x4200)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_Rm] = (instr & 0x38)>>3;
			res->fields_mask[FIELD_Rm >> 6] |= 1LL << (FIELD_Rm & 63);
			char Rm_width = 3;
			res->fields[FIELD_Rn] = instr & 0x7;
			res->fields_mask[FIELD_Rn >> 6] |= 1LL << (FIELD_Rn & 63);
			char Rn_width = 3;

			static const instruction_format instr_formats[] =
			{
				{ /* TST<c> <Rn>,<Rm> */
					"tst", /* .operation (const char *) */
					0|INSTR_FORMAT_FLAG_CONDITIONAL, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_REG,FIELD_Rm,FIELD_UNINIT,"","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					2 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_TST;

			/* pcode: n = UInt(Rn) */
			res->fields[FIELD_n] = (res->fields[FIELD_Rn]);
			res->fields_mask[FIELD_n >> 6] |= 1LL << (FIELD_n & 63);
			/* pcode: m = UInt(Rm) */
			res->fields[FIELD_m] = (res->fields[FIELD_Rm]);
			res->fields_mask[FIELD_m >> 6] |= 1LL << (FIELD_m & 63);
			/* pcode: (shift_t, shift_n) = (SRType_LSL, 0) */
			res->fields[FIELD_shift_t] = 0;
			res->fields_mask[FIELD_shift_t >> 6] |= 1LL << (FIELD_shift_t & 63);
			res->fields[FIELD_shift_n] = 0;
			res->fields_mask[FIELD_shift_n >> 6] |= 1LL << (FIELD_shift_n & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 9A9C7021
int udf(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="1101,1110,imm8.8" width=16 stringency=8 */
	{
		uint16_t instr = req->instr_word16;
		if(((instr & 0xFF00)==0xDE00)) {
			res->instrSize = 16;
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			res->fields[FIELD_imm8] = instr & 0xFF;
			res->fields_mask[FIELD_imm8 >> 6] |= 1LL << (FIELD_imm8 & 63);
			char imm8_width = 8;

			static const instruction_format instr_formats[] =
			{
				{ /* UDF #<imm8> */
					"udf", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"#","",WRITEBACK_NO},
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					1 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_UDF;

			/* pcode: imm32 = ZeroExtend(imm8, 32) */
			res->fields[FIELD_imm32] = res->fields[FIELD_imm8];
			res->fields_mask[FIELD_imm32 >> 6] |= 1LL << (FIELD_imm32 & 63);

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: A68164B3
int undefined(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)" width=16 stringency=16 */
	{
		uint16_t instr = req->instr_word16;
		if(1) {
			res->instrSize = 16;
			if(!((instr & 0xFFFF)==0x0)) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			static const instruction_format instr_formats[] =
			{
				{ /* UNDEFINED */
					"undefined", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					0 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_UNDEFINED;

			/* pcode: UNDEFINED */
			res->status |= STATUS_UNDEFINED;

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: 6BD13728
int undefined32(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)" width=32 stringency=32 */
	{
		uint32_t instr = req->instr_word32;
		if(1) {
			res->instrSize = 32;
			if(!((instr & 0xFFFFFFFF)==0x0)) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			static const instruction_format instr_formats[] =
			{
				{ /* UNDEFINED */
					"undefined", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					0 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_UNDEFINED;

			/* pcode: UNDEFINED */
			res->status |= STATUS_UNDEFINED;

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}

// gen_crc: B1B540C4
int unpredictable(struct decomp_request *req, struct decomp_result *res)
{
	int rc = -1;

	res->group = INSN_GROUP_UNKNOWN;
	/* Encoding T1 */
	/* pattern="(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)(0)" width=16 stringency=16 */
	{
		uint16_t instr = req->instr_word16;
		if(1) {
			res->instrSize = 16;
			if(!((instr & 0xFFFF)==0x0)) {
				res->flags |= FLAG_UNPREDICTABLE;
			}
			if(!(req->arch & ARCH_ARMv4T) && !(req->arch & ARCH_ARMv5T) && !(req->arch & ARCH_ARMv6) && !(req->arch & ARCH_ARMv7)) {
				res->status |= STATUS_ARCH_UNSUPPORTED;
			}
			res->fields[FIELD_cond] = armv5::COND_AL;
			res->fields_mask[FIELD_cond >> 6] |= 1LL << (FIELD_cond & 63);
			static const instruction_format instr_formats[] =
			{
				{ /* UNPREDICTABLE */
					"unpredictable", /* .operation (const char *) */
					0, /* .operationFlags (uint32_t) */
					{/* .operands (instruction_operand_format) */
						{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},
					},
					0 /* .operandCount */
				},
			}; /* ENDS instruction_format array */

			res->formats = instr_formats;
			res->formatCount = 1;
			res->mnem = armv5::ARMV5_UNPREDICTABLE;

			/* pcode: UNPREDICTABLE */
			res->flags |= FLAG_UNPREDICTABLE;

			return success();
		} /* ENDS if(<encoding_match_test>) ... */
	} /* ENDS single encoding block */

	/* if fall-thru here, no encoding block matched */
	return undefined(req, res);
}



#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
