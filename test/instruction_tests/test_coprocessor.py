"""Tests for ARM coprocessor instructions.

Tests CDP, MCR, MRC, LDC, STC, MCRR, MRRC instructions.
Only testing coprocessors p14/p15 which are valid system coprocessors.
"""
from __future__ import annotations

import pytest

from test.helpers import assert_instruction_case


COPROCESSOR_TESTS = [
    # CDP - Coprocessor Data Processing (opcodes show without # prefix)
    {
        'name': 'CDP basic - p14',
        'instruction': 0xee000e00,  # cdp p14, 0, c0, c0, c0, 0
        'address': 0x1000,
        'expected_mnemonic': 'cdp',
        'expected_operands': ['p14', '0', 'c0', 'c0', 'c0', '0'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'CDP with opcodes - p15',
        'instruction': 0xee123f45,  # cdp p15, 1, c3, c2, c5, 2
        'address': 0x1000,
        'expected_mnemonic': 'cdp',
        'expected_operands': ['p15', '1', 'c3', 'c2', 'c5', '2'],
        'expected_info': {'length': 4},
    },

    # MCR - Move to Coprocessor from ARM Register
    {
        'name': 'MCR basic - p15',
        'instruction': 0xee010f10,  # mcr p15, 0, r0, c1, c0, 0
        'address': 0x1000,
        'expected_mnemonic': 'mcr',
        'expected_operands': ['p15', '0', 'r0', 'c1', 'c0', '0'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MCR with opcodes - p14',
        'instruction': 0xee213e14,  # mcr p14, 1, r3, c1, c4, 0
        'address': 0x1000,
        'expected_mnemonic': 'mcr',
        'expected_operands': ['p14', '1', 'r3', 'c1', 'c4', '0'],
        'expected_info': {'length': 4},
    },

    # MRC - Move to ARM Register from Coprocessor
    {
        'name': 'MRC basic - p15',
        'instruction': 0xee110f10,  # mrc p15, 0, r0, c1, c0, 0
        'address': 0x1000,
        'expected_mnemonic': 'mrc',
        'expected_operands': ['p15', '0', 'r0', 'c1', 'c0', '0'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MRC ID register - p15 c0',
        'instruction': 0xee100f10,  # mrc p15, 0, r0, c0, c0, 0
        'address': 0x1000,
        'expected_mnemonic': 'mrc',
        'expected_operands': ['p15', '0', 'r0', 'c0', 'c0', '0'],
        'expected_info': {'length': 4},
    },

    # Conditional coprocessor instructions
    {
        'name': 'MCR conditional - EQ',
        'instruction': 0x0e010f10,  # mcreq p15, 0, r0, c1, c0, 0
        'address': 0x1000,
        'expected_mnemonic': 'mcreq',
        'expected_operands': ['p15', '0', 'r0', 'c1', 'c0', '0'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MRC conditional - NE',
        'instruction': 0x1e110f10,  # mrcne p15, 0, r0, c1, c0, 0
        'address': 0x1000,
        'expected_mnemonic': 'mrcne',
        'expected_operands': ['p15', '0', 'r0', 'c1', 'c0', '0'],
        'expected_info': {'length': 4},
    },

    # MCRR - Move to Coprocessor from two ARM Registers (ARMv5TE)
    {
        'name': 'MCRR basic',
        'instruction': 0xec410e00,  # mcrr p14, 0, r0, r1, c0
        'address': 0x1000,
        'expected_mnemonic': 'mcrr',
        'expected_operands': ['p14', '0', 'r0', 'r1', 'c0'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MCRR with opcode',
        'instruction': 0xec410e20,  # mcrr p14, 2, r0, r1, c0
        'address': 0x1000,
        'expected_mnemonic': 'mcrr',
        'expected_operands': ['p14', '2', 'r0', 'r1', 'c0'],
        'expected_info': {'length': 4},
    },

    # MRRC - Move to two ARM Registers from Coprocessor (ARMv5TE)
    {
        'name': 'MRRC basic',
        'instruction': 0xec510e00,  # mrrc p14, 0, r0, r1, c0
        'address': 0x1000,
        'expected_mnemonic': 'mrrc',
        'expected_operands': ['p14', '0', 'r0', 'r1', 'c0'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MRRC with different registers',
        'instruction': 0xec532e00,  # mrrc p14, 0, r2, r3, c0
        'address': 0x1000,
        'expected_mnemonic': 'mrrc',
        'expected_operands': ['p14', '0', 'r2', 'r3', 'c0'],
        'expected_info': {'length': 4},
    },

    # LDC - Load Coprocessor
    {
        'name': 'LDC basic',
        'instruction': 0xed901e01,  # ldc p14, c1, [r0, #4]
        'address': 0x1000,
        'expected_mnemonic': 'ldc',
        'expected_operands': ['p14', 'c1', '[r0, #0x4]'],
        'expected_info': {'length': 4},
    },

    # STC - Store Coprocessor
    {
        'name': 'STC basic',
        'instruction': 0xed801e01,  # stc p14, c1, [r0, #4]
        'address': 0x1000,
        'expected_mnemonic': 'stc',
        'expected_operands': ['p14', 'c1', '[r0, #0x4]'],
        'expected_info': {'length': 4},
    },
]


@pytest.mark.parametrize("case", COPROCESSOR_TESTS, ids=lambda c: c["name"])
@pytest.mark.requires_binaryninja
def test_coprocessor_cases(case, armv5_arch):
    assert_instruction_case(armv5_arch, case)
