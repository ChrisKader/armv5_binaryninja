"""Tests for edge cases and special instruction patterns.

Tests unusual but valid instruction encodings, register combinations,
and addressing modes.
"""
from __future__ import annotations

import pytest

from test.helpers import assert_instruction_case


EDGE_CASE_TESTS = [
    # PC-relative loads (common in vector tables and literal pools)
    # Note: our disassembler shows these with brackets around the address
    {
        'name': 'LDR PC-relative forward',
        'instruction': 0xe59ff004,  # ldr pc, [pc, #4]
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['pc', '[0x100c]'],  # Shows computed address in brackets
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDR r0 from PC-relative',
        'instruction': 0xe59f0010,  # ldr r0, [pc, #0x10]
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[0x1018]'],  # PC+8+0x10 = 0x1018
        'expected_info': {'length': 4},
    },

    # All condition codes with branch
    {
        'name': 'B with HS/CS condition',
        'instruction': 0x2afffffc,  # bhs/bcs
        'address': 0x1000,
        'expected_mnemonic': 'bhs',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with LO/CC condition',
        'instruction': 0x3afffffc,  # blo/bcc
        'address': 0x1000,
        'expected_mnemonic': 'blo',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with MI condition',
        'instruction': 0x4afffffc,  # bmi
        'address': 0x1000,
        'expected_mnemonic': 'bmi',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with PL condition',
        'instruction': 0x5afffffc,  # bpl
        'address': 0x1000,
        'expected_mnemonic': 'bpl',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with VS condition',
        'instruction': 0x6afffffc,  # bvs
        'address': 0x1000,
        'expected_mnemonic': 'bvs',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with VC condition',
        'instruction': 0x7afffffc,  # bvc
        'address': 0x1000,
        'expected_mnemonic': 'bvc',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with HI condition',
        'instruction': 0x8afffffc,  # bhi
        'address': 0x1000,
        'expected_mnemonic': 'bhi',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with LS condition',
        'instruction': 0x9afffffc,  # bls
        'address': 0x1000,
        'expected_mnemonic': 'bls',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with GE condition',
        'instruction': 0xaafffffc,  # bge
        'address': 0x1000,
        'expected_mnemonic': 'bge',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with LT condition',
        'instruction': 0xbafffffc,  # blt
        'address': 0x1000,
        'expected_mnemonic': 'blt',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with GT condition',
        'instruction': 0xcafffffc,  # bgt
        'address': 0x1000,
        'expected_mnemonic': 'bgt',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B with LE condition',
        'instruction': 0xdafffffc,  # ble
        'address': 0x1000,
        'expected_mnemonic': 'ble',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },

    # Rotated immediate values
    {
        'name': 'MOV rotated immediate #0x80000000',
        'instruction': 0xe3a00102,  # mov r0, #0x80000000
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r0', '#0x80000000'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOV rotated immediate #0xFF000000',
        'instruction': 0xe3a004ff,  # mov r0, #0xff000000
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r0', '#0xff000000'],
        'expected_info': {'length': 4},
    },

    # Register shifts with maximum shift amount
    {
        'name': 'MOV with LSL #31',
        'instruction': 0xe1a00f81,  # mov r0, r1, lsl #31
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r0', 'r1', 'lsl #0x1f'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOV with LSR #32',
        'instruction': 0xe1a00021,  # mov r0, r1, lsr #32
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r0', 'r1', 'lsr #0x20'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOV with ASR #32',
        'instruction': 0xe1a00041,  # mov r0, r1, asr #32
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r0', 'r1', 'asr #0x20'],
        'expected_info': {'length': 4},
    },

    # All addressing modes
    {
        'name': 'LDR pre-indexed negative',
        'instruction': 0xe5310004,  # ldr r0, [r1, #-4]!
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1, #-0x4]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDR post-indexed negative',
        'instruction': 0xe4110004,  # ldr r0, [r1], #-4
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1]', ', #-0x4'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDR register offset with shift',
        'instruction': 0xe7910182,  # ldr r0, [r1, r2, lsl #3]
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1, r2, lsl #0x3]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDR negative register offset',
        'instruction': 0xe7110002,  # ldr r0, [r1, -r2]
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1, -r2]'],
        'expected_info': {'length': 4},
    },

    # Load/store multiple with all addressing modes
    {
        'name': 'LDMIB increment before',
        'instruction': 0xe991000f,  # ldmib r1, {r0-r3}
        'address': 0x1000,
        'expected_mnemonic': 'ldmib',
        'expected_operands': ['r1', '{r0, r1, r2, r3}'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDMDB decrement before',
        'instruction': 0xe911000f,  # ldmdb r1, {r0-r3}
        'address': 0x1000,
        'expected_mnemonic': 'ldmdb',
        'expected_operands': ['r1', '{r0, r1, r2, r3}'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STMIB increment before writeback',
        'instruction': 0xe9a1000f,  # stmib r1!, {r0-r3}
        'address': 0x1000,
        'expected_mnemonic': 'stmib',
        'expected_operands': ['r1!', '{r0, r1, r2, r3}'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STMDB decrement before writeback',
        'instruction': 0xe921000f,  # stmdb r1!, {r0-r3}
        'address': 0x1000,
        'expected_mnemonic': 'stmdb',
        'expected_operands': ['r1!', '{r0, r1, r2, r3}'],
        'expected_info': {'length': 4},
    },

    # MSR with different field masks
    {
        'name': 'MSR CPSR_x register',
        'instruction': 0xe122f000,  # msr cpsr_x, r0
        'address': 0x1000,
        'expected_mnemonic': 'msr',
        'expected_operands': ['cpsr_x', 'r0'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MSR CPSR_s register',
        'instruction': 0xe124f000,  # msr cpsr_s, r0
        'address': 0x1000,
        'expected_mnemonic': 'msr',
        'expected_operands': ['cpsr_s', 'r0'],
        'expected_info': {'length': 4},
    },

    # SWI/SVC with various immediate values
    {
        'name': 'SVC max immediate',
        'instruction': 0xefffffff,  # svc #0xffffff
        'address': 0x1000,
        'expected_mnemonic': 'svc',
        'expected_operands': ['#0xffffff'],
        'expected_info': {'length': 4},
    },

    # CLZ with high registers
    {
        'name': 'CLZ r12 result',
        'instruction': 0xe16fcf10,  # clz r12, r0
        'address': 0x1000,
        'expected_mnemonic': 'clz',
        'expected_operands': ['r12', 'r0'],
        'expected_info': {'length': 4},
    },

    # SWP with different registers
    {
        'name': 'SWP with r12',
        'instruction': 0xe101c09c,  # swp r12, r12, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'swp',
        'expected_operands': ['r12', 'r12', '[r1]'],
        'expected_info': {'length': 4},
    },

    # Halfword load/store with register offset
    {
        'name': 'LDRH register offset',
        'instruction': 0xe19100b2,  # ldrh r0, [r1, r2]
        'address': 0x1000,
        'expected_mnemonic': 'ldrh',
        'expected_operands': ['r0', '[r1, r2]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STRH register offset',
        'instruction': 0xe18100b2,  # strh r0, [r1, r2]
        'address': 0x1000,
        'expected_mnemonic': 'strh',
        'expected_operands': ['r0', '[r1, r2]'],
        'expected_info': {'length': 4},
    },

    # PLD with negative offset
    {
        'name': 'PLD negative offset',
        'instruction': 0xf551f004,  # pld [r1, #-4]
        'address': 0x1000,
        'expected_mnemonic': 'pld',
        'expected_operands': ['[r1, #-0x4]'],
        'expected_info': {'length': 4},
    },

    # BKPT with max immediate
    {
        'name': 'BKPT max immediate',
        'instruction': 0xe12fff7f,  # bkpt #0xffff
        'address': 0x1000,
        'expected_mnemonic': 'bkpt',
        'expected_operands': ['#0xffff'],
        'expected_info': {'length': 4},
    },
]


@pytest.mark.parametrize("case", EDGE_CASE_TESTS, ids=lambda c: c["name"])
@pytest.mark.requires_binaryninja
def test_edge_cases(case, armv5_arch):
    assert_instruction_case(armv5_arch, case)
