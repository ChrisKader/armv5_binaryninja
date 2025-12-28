#!/usr/bin/env python

test_cases_arm = [
	# Basic load/store with PC-relative addressing
	# ldr r0, [r1] -> r0 = load(r1)
	(b'\x00\x00\x91\xe5', 'LLIL_SET_REG(r0,LLIL_LOAD(LLIL_REG(r1)))'),
	# str r0, [r1] -> store(r1, r0)
	(b'\x00\x00\x81\xe5', 'LLIL_STORE(LLIL_REG(r1),LLIL_REG(r0))'),

	# Data processing
	# add r0, r2, r1 -> r0 = r2 + r1
	(b'\x01\x00\x82\xe0', 'LLIL_SET_REG(r0,LLIL_ADD(LLIL_REG(r2),LLIL_REG(r1)))'),
	# sub r0, r2, r1 -> r0 = r2 - r1
	(b'\x01\x00\x42\xe0', 'LLIL_SET_REG(r0,LLIL_SUB(LLIL_REG(r2),LLIL_REG(r1)))'),
	# and r0, r2, r1 -> r0 = r2 & r1
	(b'\x01\x00\x02\xe0', 'LLIL_SET_REG(r0,LLIL_AND(LLIL_REG(r2),LLIL_REG(r1)))'),
	# orr r0, r2, r1 -> r0 = r2 | r1
	(b'\x01\x00\x82\xe1', 'LLIL_SET_REG(r0,LLIL_OR(LLIL_REG(r2),LLIL_REG(r1)))'),
	# eor r0, r2, r1 -> r0 = r2 ^ r1
	(b'\x01\x00\x22\xe0', 'LLIL_SET_REG(r0,LLIL_XOR(LLIL_REG(r2),LLIL_REG(r1)))'),

	# Long multiply: umull r0, r1, r2, r3
	(b'\x92\x03\x81\xe0', 'LLIL_SET_REG_SPLIT(r1,r0,LLIL_MULU_DP(LLIL_REG(r2),LLIL_REG(r3)))'),
	# Long multiply: smull r0, r1, r2, r3
	(b'\x92\x03\xc1\xe0', 'LLIL_SET_REG_SPLIT(r1,r0,LLIL_MULS_DP(LLIL_REG(r2),LLIL_REG(r3)))'),

	# Multiply and accumulate: mla r0, r1, r2, r3 -> r0 = r3 + (r1 * r2)
	(b'\x91\x32\x20\xe0', 'LLIL_SET_REG(r0,LLIL_ADD(LLIL_REG(r3),LLIL_MUL(LLIL_REG(r1),LLIL_REG(r2))))'),

	# mov r0, r1 -> r0 = r1
	(b'\x01\x00\xa0\xe1', 'LLIL_SET_REG(r0,LLIL_REG(r1))'),
	# mov r0, #5 -> r0 = 5
	(b'\x05\x00\xa0\xe3', 'LLIL_SET_REG(r0,LLIL_CONST(5))'),

	# NOP (mov r0, r0) - optimized to empty by BN since we decode as ARMV5_NOP
	(b'\x00\x00\xa0\xe1', ''),
]

# Instructions that should be rejected as likely data (IsLikelyData returns true)
# These produce empty IL because GetInstructionInfo returns false
test_cases_likely_data = [
	# Pattern 6b: Long multiply with S flag AND conditional execution
	# Literal pool pointers like 0x10bxxxxx decode as "umlalsne"
	# 0x10b82490: umlalsne r2, r8, r0, r4 - S flag + NE condition
	(b'\x90\x24\xb8\x10', ''),
	# 0x10b67290: umlalsne r7, r6, r0, r2 - S flag + NE condition
	(b'\x90\x72\xb6\x10', ''),
	# 0x10b5fd9c: umlalsne pc, r5, r12, sp - PC as RdLo, SP as Rs
	(b'\x9c\xfd\xb5\x10', ''),

	# Pattern: RSC is extremely rare
	# 0x00edb910: rsceq r11, sp, r0, lsl r9
	(b'\x10\xb9\xed\x00', ''),

	# Pattern 8: Coprocessor to unusual coprocessor (p9)
	# 0x4cecb910: stcmi p9, c11, [r12], #0x40
	(b'\x10\xb9\xec\x4c', ''),
	# 0x3cedb910: stclo p9, c11, [sp], #0x40
	(b'\x10\xb9\xed\x3c', ''),

	# Pattern 6b: SMULL with PC as source
	# 0x20d01f9f: smullshs r1, r0, pc, pc - PC as both Rm and Rs
	(b'\x9f\x1f\xd0\x20', ''),

	# Pattern 6b: SMLAL with LR as RdHi
	# 0x00fec19d: smlalseq r12, lr, sp, r1 - LR as RdHi, SP as Rm
	(b'\x9d\xc1\xfe\x00', ''),
]

test_cases_thumb = [
	# Thumb mode LLIL tests would go here
	# Basic Thumb tests - minimal for now
]

import sys
import binaryninja
from binaryninja import core
from binaryninja import binaryview
from binaryninja import lowlevelil

def il2str(il):
	if isinstance(il, lowlevelil.LowLevelILInstruction):
		return '%s(%s)' % (il.operation.name, ','.join([il2str(o) for o in il.operands]))
	else:
		return str(il)

# TODO: make this less hacky
def instr_to_il(data, arch_name, expect_rejected=False):
	arch = binaryninja.Architecture[arch_name]
	plat = arch.standalone_platform
	# make a pretend function that returns

	sled = b''
	sled_len = 0x1000
	if arch_name == 'armv5t':
		sled = b'\xc0\x46' * (sled_len//2)  # Thumb NOP (mov r8, r8)
	elif arch_name == 'armv5':
		sled = b'\x00\x00\xa0\xe1' * (sled_len//4)  # ARM NOP (mov r0, r0)

	bv = binaryview.BinaryView.new(sled + data)
	bv.add_function(sled_len, plat=plat)

	# If instruction is rejected by GetInstructionInfo, no function is created
	# at that address, or function analysis stops at that point
	if len(bv.functions) == 0:
		return '' if expect_rejected else 'NO_FUNCTION'

	result = []
	for block in bv.functions[0].low_level_il:
		for il in block:
			result.append(il2str(il))
	result = '; '.join(result)

	# If instruction was rejected, we won't see LLIL_UNDEF at expected position
	if not result.endswith('LLIL_UNDEF()'):
		# The function stopped before reaching our instruction
		return '' if expect_rejected else result

	result = result[0:result.index('LLIL_UNDEF()')]
	if result.endswith('; '):
		result = result[0:-2]

	return result

def check(test_i, data, actual, expected):
	print_always = False

	if (actual != expected) or print_always:
		print('\t    test: %d' % test_i)
		print('\t   input: %s' % data.hex())
		print('\texpected: %s' % expected)
		print('\t  actual: %s' % actual)

	if actual != expected:
		print('MISMATCH!')
		sys.exit(-1)

if __name__ == '__main__':
	print('Testing ARM mode instructions...')
	for (test_i, (data, expected)) in enumerate(test_cases_arm):
		actual = instr_to_il(data, 'armv5')
		check(test_i, data, actual, expected)
	print(f'  {len(test_cases_arm)} ARM tests passed')

	print('Testing Thumb mode instructions...')
	for (test_i, (data, expected)) in enumerate(test_cases_thumb):
		actual = instr_to_il(data, 'armv5t')
		check(test_i, data, actual, expected)
	print(f'  {len(test_cases_thumb)} Thumb tests passed')

	print('Testing IsLikelyData patterns (should produce empty IL)...')
	for (test_i, (data, expected)) in enumerate(test_cases_likely_data):
		actual = instr_to_il(data, 'armv5', expect_rejected=True)
		check(test_i, data, actual, expected)
	print(f'  {len(test_cases_likely_data)} IsLikelyData tests passed')

	print('success!')
	sys.exit(0)
