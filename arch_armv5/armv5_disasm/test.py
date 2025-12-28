#!/usr/bin/env python

# compile disassembler to ctypes-able shared object:
# MAC: gcc armv5.c -shared -o disasm.dylib

# (bytes, expected_disassembly, options)
test_cases = (
	# msr, mrs
	(b'\x00\x00\x0f\xe1', 'mrs r0, cpsr', {}),
	(b'\x00\x80\x0f\xe1', 'mrs r8, cpsr', {}),
	(b'\x00\x00\x4f\xe1', 'mrs r0, spsr', {}),
	(b'\x00\x80\x4f\xe1', 'mrs r8, spsr', {}),
	# MSR register
	(b'\x00\xf0\x29\xe1', 'msr cpsr_fc, r0', {}),
	(b'\x00\xf0\x21\xe1', 'msr cpsr_c, r0', {}),
	(b'\x00\xf0\x22\xe1', 'msr cpsr_x, r0', {}),
	(b'\x00\xf0\x24\xe1', 'msr cpsr_s, r0', {}),
	(b'\x00\xf0\x28\xe1', 'msr cpsr_f, r0', {}),
	(b'\x00\xf0\x2f\xe1', 'msr cpsr_fsxc, r0', {}),
	(b'\x00\xf0\x69\xe1', 'msr spsr_fc, r0', {}),
	(b'\x00\xf0\x6f\xe1', 'msr spsr_fsxc, r0', {}),
	# MSR immediate
	(b'\x05\xf0\x29\xe3', 'msr cpsr_fc, #0x5', {}),
	(b'\x05\xf0\x21\xe3', 'msr cpsr_c, #0x5', {}),
	(b'\x05\xf0\x2f\xe3', 'msr cpsr_fsxc, #0x5', {}),
	(b'\x05\xf0\x69\xe3', 'msr spsr_fc, #0x5', {}),

	# supervisor calls
	(b'\x10\x00\x00\xef', 'svc #0x10', {}),
	(b'\x00\x00\x00\xef', 'svc #0', {}),
	(b'\xff\xff\xff\xef', 'svc #0xffffff', {}),
	(b'\x01\x00\x00\xef', 'svc #0x1', {}),
	(b'\x02\x00\x00\xef', 'svc #0x2', {}),
	(b'\x56\x34\x12\xef', 'svc #0x123456', {}),

	# BKPT (ARMv5+)
	(b'\x70\x00\x20\xe1', 'bkpt #0', {}),
	(b'\x71\x00\x20\xe1', 'bkpt #0x1', {}),
	(b'\x7f\xff\x2f\xe1', 'bkpt #0xffff', {}),

	# Data processing - register
	(b'\x01\x00\x80\xe0', 'add r0, r0, r1', {}),
	(b'\x01\x00\x82\xe0', 'add r0, r2, r1', {}),
	(b'\x01\x00\x42\xe0', 'sub r0, r2, r1', {}),
	(b'\x01\x00\x62\xe0', 'rsb r0, r2, r1', {}),
	(b'\x01\x00\x02\xe0', 'and r0, r2, r1', {}),
	(b'\x01\x00\x82\xe1', 'orr r0, r2, r1', {}),
	(b'\x01\x00\x22\xe0', 'eor r0, r2, r1', {}),
	(b'\x01\x00\xc2\xe1', 'bic r0, r2, r1', {}),
	(b'\x01\x00\xa2\xe0', 'adc r0, r2, r1', {}),
	(b'\x01\x00\xc2\xe0', 'sbc r0, r2, r1', {}),
	(b'\x01\x00\xe2\xe0', 'rsc r0, r2, r1', {}),
	# With S flag
	(b'\x01\x00\x92\xe0', 'adds r0, r2, r1', {}),
	(b'\x01\x00\x52\xe0', 'subs r0, r2, r1', {}),

	# MOV/MVN
	(b'\x01\x00\xa0\xe1', 'mov r0, r1', {}),
	(b'\x02\x10\xa0\xe1', 'mov r1, r2', {}),
	(b'\x01\x00\xe0\xe1', 'mvn r0, r1', {}),
	(b'\x05\x00\xa0\xe3', 'mov r0, #0x5', {}),
	(b'\xff\x00\xa0\xe3', 'mov r0, #0xff', {}),
	(b'\x01\x01\xa0\xe3', 'mov r0, #0x40000000', {}),
	(b'\x05\x00\xe0\xe3', 'mvn r0, #0x5', {}),
	# With S flag
	(b'\x01\x00\xb0\xe1', 'movs r0, r1', {}),
	(b'\x01\x00\xf0\xe1', 'mvns r0, r1', {}),

	# Compare/test
	(b'\x01\x00\x52\xe1', 'cmp r2, r1', {}),
	(b'\x01\x00\x72\xe1', 'cmn r2, r1', {}),
	(b'\x01\x00\x12\xe1', 'tst r2, r1', {}),
	(b'\x01\x00\x32\xe1', 'teq r2, r1', {}),
	# With immediate
	(b'\x05\x00\x52\xe3', 'cmp r2, #0x5', {}),
	(b'\x05\x00\x72\xe3', 'cmn r2, #0x5', {}),
	(b'\x05\x00\x12\xe3', 'tst r2, #0x5', {}),
	(b'\x05\x00\x32\xe3', 'teq r2, #0x5', {}),

	# Shifts (immediate)
	(b'\x81\x00\xa0\xe1', 'mov r0, r1, lsl #0x1', {}),
	(b'\x01\x01\xa0\xe1', 'mov r0, r1, lsl #0x2', {}),
	(b'\xa1\x00\xa0\xe1', 'mov r0, r1, lsr #0x1', {}),
	(b'\x21\x04\xa0\xe1', 'mov r0, r1, lsr #0x8', {}),
	(b'\xc1\x00\xa0\xe1', 'mov r0, r1, asr #0x1', {}),
	(b'\x41\x04\xa0\xe1', 'mov r0, r1, asr #0x8', {}),
	(b'\xe1\x00\xa0\xe1', 'mov r0, r1, ror #0x1', {}),
	(b'\x61\x04\xa0\xe1', 'mov r0, r1, ror #0x8', {}),
	(b'\x61\x00\xa0\xe1', 'mov r0, r1, rrx', {}),

	# Shifts (register)
	(b'\x11\x02\xa0\xe1', 'mov r0, r1, lsl r2', {}),
	(b'\x31\x02\xa0\xe1', 'mov r0, r1, lsr r2', {}),
	(b'\x51\x02\xa0\xe1', 'mov r0, r1, asr r2', {}),
	(b'\x71\x02\xa0\xe1', 'mov r0, r1, ror r2', {}),

	# Branches
	(b'\xfe\xff\xff\xea', 'b 0', {}),
	(b'\x00\x00\x00\xea', 'b 0x8', {}),
	(b'\x00\x00\x00\xeb', 'bl 0x8', {}),
	(b'\xfd\xff\xff\xeb', 'bl 0xfffffffc', {}),
	# BX/BLX
	(b'\x11\xff\x2f\xe1', 'bx r1', {}),
	(b'\x1e\xff\x2f\xe1', 'bx lr', {}),
	(b'\x10\xff\x2f\xe1', 'bx r0', {}),
	(b'\x31\xff\x2f\xe1', 'blx r1', {}),
	(b'\x3e\xff\x2f\xe1', 'blx lr', {}),
	# BLX immediate (unconditional)
	(b'\x00\x00\x00\xfa', 'blx 0x8', {}),

	# Load/store word
	(b'\x00\x00\x91\xe5', 'ldr r0, [r1]', {}),
	(b'\x04\x00\x91\xe5', 'ldr r0, [r1, #0x4]', {}),
	(b'\x04\x00\x11\xe5', 'ldr r0, [r1, #-0x4]', {}),
	(b'\x00\x00\x81\xe5', 'str r0, [r1]', {}),
	(b'\x04\x00\x81\xe5', 'str r0, [r1, #0x4]', {}),

	# Load/store byte
	(b'\x00\x00\xd1\xe5', 'ldrb r0, [r1]', {}),
	(b'\x04\x00\xd1\xe5', 'ldrb r0, [r1, #0x4]', {}),
	(b'\x00\x00\xc1\xe5', 'strb r0, [r1]', {}),

	# Load/store halfword
	(b'\xb0\x00\xd1\xe1', 'ldrh r0, [r1]', {}),
	(b'\xb4\x00\xd1\xe1', 'ldrh r0, [r1, #0x4]', {}),
	(b'\xb0\x00\xc1\xe1', 'strh r0, [r1]', {}),

	# Signed load
	(b'\xd0\x00\xd1\xe1', 'ldrsb r0, [r1]', {}),
	(b'\xf0\x00\xd1\xe1', 'ldrsh r0, [r1]', {}),

	# Load/store doubleword (ARMv5TE)
	(b'\xd0\x00\xc1\xe1', 'ldrd r0, r1, [r1]', {}),
	(b'\xf0\x00\xc1\xe1', 'strd r0, r1, [r1]', {}),

	# Pre-indexed
	(b'\x04\x00\xb1\xe5', 'ldr r0, [r1, #0x4]!', {}),
	(b'\x04\x00\xa1\xe5', 'str r0, [r1, #0x4]!', {}),

	# Post-indexed
	(b'\x04\x00\x91\xe4', 'ldr r0, [r1], #0x4', {}),
	(b'\x04\x00\x81\xe4', 'str r0, [r1], #0x4', {}),

	# Load/store multiple
	(b'\x0f\x00\x91\xe8', 'ldmia r1, {r0, r1, r2, r3}', {}),
	(b'\x0f\x00\x81\xe8', 'stmia r1, {r0, r1, r2, r3}', {}),
	(b'\x0f\x00\xb1\xe8', 'ldmia r1!, {r0, r1, r2, r3}', {}),
	(b'\x0f\x00\xa1\xe8', 'stmia r1!, {r0, r1, r2, r3}', {}),

	# PUSH/POP (special case of STMDB/LDMIA with sp)
	(b'\xf0\x41\x2d\xe9', 'push {r4, r5, r6, r7, r8, lr}', {}),
	(b'\xf0\x81\xbd\xe8', 'pop {r4, r5, r6, r7, r8, pc}', {}),

	# Multiply
	(b'\x92\x01\x00\xe0', 'mul r0, r2, r1', {}),
	(b'\x92\x01\x10\xe0', 'muls r0, r2, r1', {}),
	(b'\x92\x31\x20\xe0', 'mla r0, r2, r1, r3', {}),
	(b'\x92\x31\x30\xe0', 'mlas r0, r2, r1, r3', {}),

	# Long multiply
	(b'\x92\x01\x80\xe0', 'umull r0, r0, r2, r1', {}),
	(b'\x92\x01\xa0\xe0', 'umlal r0, r0, r2, r1', {}),
	(b'\x92\x01\xc0\xe0', 'smull r0, r0, r2, r1', {}),
	(b'\x92\x01\xe0\xe0', 'smlal r0, r0, r2, r1', {}),

	# DSP multiply (ARMv5TE)
	(b'\x82\x01\x60\xe1', 'smulbb r0, r2, r1', {}),
	(b'\xc2\x01\x60\xe1', 'smulbt r0, r2, r1', {}),
	(b'\xa2\x01\x60\xe1', 'smultb r0, r2, r1', {}),
	(b'\xe2\x01\x60\xe1', 'smultt r0, r2, r1', {}),
	(b'\xa2\x01\x20\xe1', 'smulwb r0, r2, r1', {}),
	(b'\xe2\x01\x20\xe1', 'smulwt r0, r2, r1', {}),
	(b'\x82\x31\x00\xe1', 'smlabb r0, r2, r1, r3', {}),
	(b'\xc2\x31\x00\xe1', 'smlabt r0, r2, r1, r3', {}),
	(b'\xa2\x31\x00\xe1', 'smlatb r0, r2, r1, r3', {}),
	(b'\xe2\x31\x00\xe1', 'smlatt r0, r2, r1, r3', {}),
	(b'\x82\x31\x20\xe1', 'smlawb r0, r2, r1, r3', {}),
	(b'\xc2\x31\x20\xe1', 'smlawt r0, r2, r1, r3', {}),
	(b'\x82\x01\x40\xe1', 'smlalbb r0, r0, r2, r1', {}),
	(b'\xc2\x01\x40\xe1', 'smlalbt r0, r0, r2, r1', {}),
	(b'\xa2\x01\x40\xe1', 'smlaltb r0, r0, r2, r1', {}),
	(b'\xe2\x01\x40\xe1', 'smlaltt r0, r0, r2, r1', {}),

	# CLZ (ARMv5+)
	(b'\x11\x0f\x6f\xe1', 'clz r0, r1', {}),
	(b'\x12\x1f\x6f\xe1', 'clz r1, r2', {}),
	(b'\x1e\x0f\x6f\xe1', 'clz r0, lr', {}),

	# Saturating arithmetic (ARMv5TE)
	(b'\x52\x00\x01\xe1', 'qadd r0, r2, r1', {}),
	(b'\x52\x00\x21\xe1', 'qsub r0, r2, r1', {}),
	(b'\x52\x00\x41\xe1', 'qdadd r0, r2, r1', {}),
	(b'\x52\x00\x61\xe1', 'qdsub r0, r2, r1', {}),

	# SWP (deprecated but valid in ARMv5)
	(b'\x92\x00\x01\xe1', 'swp r0, r2, [r1]', {}),
	(b'\x92\x00\x41\xe1', 'swpb r0, r2, [r1]', {}),

	# Coprocessor
	(b'\x02\x01\x23\xee', 'cdp p1, #0x2, c0, c3, c2, #0', {}),
	(b'\x10\x01\x02\xee', 'mcr p1, #0, r0, c2, c0, #0', {}),
	(b'\x10\x01\x12\xee', 'mrc p1, #0, r0, c2, c0, #0', {}),
	(b'\x00\x01\x91\xed', 'ldc p1, c0, [r1]', {}),
	(b'\x00\x01\x81\xed', 'stc p1, c0, [r1]', {}),

	# PLD (ARMv5TE)
	(b'\x00\xf0\xd1\xf5', 'pld [r1]', {}),
	(b'\x04\xf0\xd1\xf5', 'pld [r1, #0x4]', {}),

	# Conditional execution
	(b'\x01\x00\x82\x00', 'addeq r0, r2, r1', {}),
	(b'\xfe\xff\xff\x0a', 'beq 0', {}),
	(b'\x01\x00\x82\x10', 'addne r0, r2, r1', {}),
	(b'\xfe\xff\xff\x1a', 'bne 0', {}),
	(b'\x01\x00\x82\x20', 'addhs r0, r2, r1', {}),
	(b'\xfe\xff\xff\x2a', 'bhs 0', {}),
	(b'\x01\x00\x82\x30', 'addlo r0, r2, r1', {}),
	(b'\xfe\xff\xff\x3a', 'blo 0', {}),
	(b'\x01\x00\x82\x40', 'addmi r0, r2, r1', {}),
	(b'\x01\x00\x82\x50', 'addpl r0, r2, r1', {}),
	(b'\x01\x00\x82\x60', 'addvs r0, r2, r1', {}),
	(b'\x01\x00\x82\x70', 'addvc r0, r2, r1', {}),
	(b'\x01\x00\x82\x80', 'addhi r0, r2, r1', {}),
	(b'\x01\x00\x82\x90', 'addls r0, r2, r1', {}),
	(b'\x01\x00\x82\xa0', 'addge r0, r2, r1', {}),
	(b'\x01\x00\x82\xb0', 'addlt r0, r2, r1', {}),
	(b'\x01\x00\x82\xc0', 'addgt r0, r2, r1', {}),
	(b'\x01\x00\x82\xd0', 'addle r0, r2, r1', {}),
	(b'\x01\x00\x82\xe0', 'add r0, r2, r1', {}),

	# NOP (mov r0, r0)
	(b'\x00\x00\xa0\xe1', 'mov r0, r0', {}),

	# VFP (VFPv2 - ARMv5TE optional)
	(b'\x01\x0a\x30\xee', 'vadd.f32 s0, s0, s2', {}),
	(b'\x41\x0a\x30\xee', 'vsub.f32 s0, s0, s2', {}),
	(b'\x01\x0a\x20\xee', 'vmul.f32 s0, s0, s2', {}),
	(b'\x01\x0a\x80\xee', 'vdiv.f32 s0, s0, s2', {}),
	(b'\x00\x0a\x91\xed', 'vldr s0, [r1]', {}),
	(b'\x00\x0a\x81\xed', 'vstr s0, [r1]', {}),
)

import os, sys, struct, platform, re
from ctypes import *

module = None
disasm_buf = create_string_buffer(2048)
inst_buf = create_string_buffer(2048)

def disassemble_binja(insvalue, addr):
	global module, disasm_buf, inst_buf
	for a in range(len(disasm_buf)):
		disasm_buf[a] = b'\0'
	for a in range(len(inst_buf)):
		inst_buf[a] = b'\0'
	err = module.armv5_decompose(insvalue, inst_buf, addr, False)
	if err == 1: return "decomposer failed"
	elif err == 2: return "group decomposition failed"
	elif err == 3: return "unimplemented"
	elif err == 4: return "disassembler failed"
	if module.armv5_disassemble(inst_buf, disasm_buf, 2048) == 0:
		return disasm_buf.value.decode('utf-8')
	return "disassembly failed"

def distill(instxt):
	instxt = re.sub(r'\s+', ' ', instxt)
	return instxt

if __name__ == '__main__':
	if platform.system() == 'Linux': module = CDLL('disasm.so')
	elif platform.system() == 'Windows': module = CDLL('disasm.dll')
	# gcc -shared armv5.c -o disasm.dylib
	elif platform.system() == "Darwin": module = CDLL('disasm.dylib')

	for (test_i, (data, expected, options)) in enumerate(test_cases):
		addr = options.get('addr', 0)
		insvalue = struct.unpack('<I', data)[0]
		actual = disassemble_binja(insvalue, addr)
		actual = distill(actual)
		if actual != expected:
			print('MISMATCH AT TEST %d!' % test_i)
			print('\t    data: %s' % repr(data))
			print('\t address: %08X' % addr)
			print('\tinsvalue: 0x%08X' % insvalue)
			print('\texpected: %s' % expected)
			print('\t  actual: %s' % actual)
			sys.exit(-1)

	print('success!')
	sys.exit(0)
