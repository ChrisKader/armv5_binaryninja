#!/usr/bin/env python

# (bytes, expected_disassembly, options)
# ARMv5 Thumb test cases - 16-bit instructions only
# Encodings derived from spec.txt
test_cases = (
	# NOP (mov r8, r8)
	(b'\x00\xbf', 'nop', {}),

	# Data processing - shifts
	(b'\x00\x00', 'movs r0, r0', {}),           # lsl r0, r0, #0 -> movs r0, r0
	(b'\x49\x00', 'lsls r1, r1, #0x1', {}),     # lsl r1, r1, #1
	(b'\x08\x08', 'lsrs r0, r1, #0x20', {}),    # lsr r0, r1, #32
	(b'\x08\x10', 'asrs r0, r1, #0x20', {}),    # asr r0, r1, #32

	# Data processing - add/sub register
	(b'\xc0\x18', 'adds r0, r0, r3', {}),       # add r0, r0, r3
	(b'\xc0\x1a', 'subs r0, r0, r3', {}),       # sub r0, r0, r3

	# Data processing - add/sub immediate
	(b'\x40\x1c', 'adds r0, r0, #0x1', {}),     # add r0, r0, #1
	(b'\x40\x1e', 'subs r0, r0, #0x1', {}),     # sub r0, r0, #1

	# Data processing - mov/cmp immediate
	(b'\x00\x20', 'movs r0, #0x0', {}),         # mov r0, #0
	(b'\xff\x20', 'movs r0, #0xff', {}),        # mov r0, #255
	(b'\x00\x28', 'cmp r0, #0x0', {}),          # cmp r0, #0
	(b'\x01\x29', 'cmp r1, #0x1', {}),          # cmp r1, #1

	# Data processing - register operations
	(b'\x08\x40', 'ands r0, r1', {}),           # and r0, r1
	(b'\x48\x40', 'eors r0, r1', {}),           # eor r0, r1
	(b'\x88\x40', 'lsls r0, r1', {}),           # lsl r0, r1
	(b'\xc8\x40', 'lsrs r0, r1', {}),           # lsr r0, r1
	(b'\x08\x41', 'asrs r0, r1', {}),           # asr r0, r1
	(b'\x48\x41', 'adcs r0, r1', {}),           # adc r0, r1
	(b'\x88\x41', 'sbcs r0, r1', {}),           # sbc r0, r1
	(b'\xc8\x41', 'rors r0, r1', {}),           # ror r0, r1
	(b'\x08\x42', 'tst r0, r1', {}),            # tst r0, r1
	(b'\x48\x42', 'rsbs r0, r1, #0x0', {}),     # rsb r0, r1, #0
	(b'\x88\x42', 'cmp r0, r1', {}),            # cmp r0, r1
	(b'\xc8\x42', 'cmn r0, r1', {}),            # cmn r0, r1
	(b'\x08\x43', 'orrs r0, r1', {}),           # orr r0, r1
	(b'\x48\x43', 'muls r0, r1, r0', {}),       # mul r0, r1
	(b'\x88\x43', 'bics r0, r1', {}),           # bic r0, r1
	(b'\xc8\x43', 'mvns r0, r1', {}),           # mvn r0, r1

	# Special data - add high regs
	(b'\x78\x44', 'add r0, pc', {}),            # add r0, pc

	# Load/store immediate offset
	(b'\x00\x60', 'str r0, [r0]', {}),          # str r0, [r0, #0]
	(b'\x00\x68', 'ldr r0, [r0]', {}),          # ldr r0, [r0, #0]
	(b'\x00\x70', 'strb r0, [r0]', {}),         # strb r0, [r0, #0]
	(b'\x00\x78', 'ldrb r0, [r0]', {}),         # ldrb r0, [r0, #0]
	(b'\x00\x80', 'strh r0, [r0]', {}),         # strh r0, [r0, #0]
	(b'\x00\x88', 'ldrh r0, [r0]', {}),         # ldrh r0, [r0, #0]

	# Load/store register offset
	(b'\x00\x50', 'str r0, [r0, r0]', {}),      # str r0, [r0, r0]
	(b'\x00\x58', 'ldr r0, [r0, r0]', {}),      # ldr r0, [r0, r0]
	(b'\x80\x5a', 'ldrh r0, [r0, r2]', {}),     # ldrh r0, [r0, r2]
	(b'\x00\x5c', 'ldrb r0, [r0, r0]', {}),     # ldrb r0, [r0, r0]
	(b'\x00\x56', 'ldrsb r0, [r0, r0]', {}),    # ldrsb r0, [r0, r0]
	(b'\x00\x5e', 'ldrsh r0, [r0, r0]', {}),    # ldrsh r0, [r0, r0]

	# Load from literal pool
	(b'\x00\x48', 'ldr r0, [pc, #0x0]', {}),    # ldr r0, [pc, #0]

	# SP-relative load/store
	(b'\x00\x90', 'str r0, [sp]', {}),          # str r0, [sp, #0]
	(b'\x00\x98', 'ldr r0, [sp]', {}),          # ldr r0, [sp, #0]

	# ADR
	(b'\x00\xa0', 'adr r0, #0x0', {}),          # adr r0, pc, #0

	# Add to SP
	(b'\x00\xa8', 'add r0, sp, #0x0', {}),      # add r0, sp, #0
	(b'\x00\xb0', 'add sp, #0x0', {}),          # add sp, #0
	(b'\x80\xb0', 'sub sp, #0x0', {}),          # sub sp, #0

	# Push/pop
	(b'\x00\xb4', 'push {}', {}),               # push {} (empty - may be undefined)
	(b'\x00\xb5', 'push {lr}', {}),             # push {lr}
	(b'\x01\xb4', 'push {r0}', {}),             # push {r0}
	(b'\x00\xbc', 'pop {}', {}),                # pop {} (empty - may be undefined)
	(b'\x00\xbd', 'pop {pc}', {}),              # pop {pc}
	(b'\x01\xbc', 'pop {r0}', {}),              # pop {r0}

	# LDM/STM
	(b'\x01\xc0', 'stm r0!, {r0}', {}),         # stmia r0!, {r0}
	(b'\x01\xc8', 'ldm r0!, {r0}', {}),         # ldmia r0!, {r0}

	# Conditional branch
	(b'\x00\xd0', 'beq 0x4', {}),               # beq +0 (target = PC+4+0*2)
	(b'\x00\xd1', 'bne 0x4', {}),               # bne +0

	# Unconditional branch
	(b'\x00\xe0', 'b 0x4', {}),                 # b +0 (target = PC+4+0*2)

	# Branch and exchange
	(b'\x00\x47', 'bx r0', {}),                 # bx r0
	(b'\x08\x47', 'bx r1', {}),                 # bx r1
	(b'\x70\x47', 'bx lr', {}),                 # bx lr
	(b'\x80\x47', 'blx r0', {}),                # blx r0

	# SVC
	(b'\x00\xdf', 'svc #0x0', {}),              # svc #0

	# BKPT (ARMv5T+)
	(b'\x00\xbe', 'bkpt #0x0', {}),             # bkpt #0
)

import sys, re
import binaryninja

arch = None
def disassemble_binja(data, addr):
	global arch
	if not arch:
		arch = binaryninja.Architecture['armv5t']
	(tokens, length) = arch.get_instruction_text(data, addr)
	if not tokens or length==0:
		return 'disassembly failed'
	strs = map(lambda x: x.text, tokens)
	instxt = ''.join(strs)
	instxt = re.sub(r'\s+', ' ', instxt)
	return instxt

if __name__ == '__main__':
	for (test_i, (data, expected, options)) in enumerate(test_cases):
		addr = options.get('addr', 0)
		actual = disassemble_binja(data, addr)
		if actual != expected:
			print('MISMATCH AT TEST %d!' % test_i)
			print('\t    data: %s' % repr(data))
			print('\t address: %08X' % addr)
			print('\texpected: %s' % expected)
			print('\t  actual: %s' % actual)
			sys.exit(-1)

	print('success!')
	sys.exit(0)

