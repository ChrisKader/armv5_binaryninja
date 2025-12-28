"""Tests for ARM branch instructions."""
from __future__ import annotations

import pytest

from test.helpers import assert_instruction_case


BRANCH_TESTS = [
    # Basic branch instructions
    {
        'name': 'B unconditional forward',
        'instruction': 0xea000010,  # b #0x44 (forward 16 instructions)
        'address': 0x1000,
        'expected_mnemonic': 'b',
        'expected_operands': ['0x1048'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B unconditional backward',
        'instruction': 0xeafffffc,  # b #-0x10 (backward 4 instructions)
        'address': 0x1000,
        'expected_mnemonic': 'b',
        'expected_operands': ['0xff8'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B zero offset (self branch)',
        'instruction': 0xeafffffe,  # b #-8 (branch to self)
        'address': 0x1000,
        'expected_mnemonic': 'b',
        'expected_operands': ['0x1000'],
        'expected_info': {'length': 4},
    },

    # Branch with Link (BL) instructions
    {
        'name': 'BL function call',
        'instruction': 0xeb000100,  # bl #0x408 (call function)
        'address': 0x1000,
        'expected_mnemonic': 'bl',
        'expected_operands': ['0x1408'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'BL short call',
        'instruction': 0xeb000001,  # bl #8 (call next function)
        'address': 0x1000,
        'expected_mnemonic': 'bl',
        'expected_operands': ['0x100c'],
        'expected_info': {'length': 4},
    },

    # Conditional branch instructions
    {
        'name': 'B conditional - EQ',
        'instruction': 0x0a000010,  # beq #0x44
        'address': 0x1000,
        'expected_mnemonic': 'beq',
        'expected_operands': ['0x1048'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'B conditional - NE',
        'instruction': 0x1a000008,  # bne #0x24
        'address': 0x1000,
        'expected_mnemonic': 'bne',
        'expected_operands': ['0x1028'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'BL conditional - CS',
        'instruction': 0x2b000020,  # blcs #0x84
        'address': 0x1000,
        'expected_mnemonic': 'blhs',
        'expected_operands': ['0x1088'],
        'expected_info': {'length': 4},
    },

    # BX/BLX register
    {
        'name': 'BX register',
        'instruction': 0xe12fff11,  # bx r1
        'address': 0x1000,
        'expected_mnemonic': 'bx',
        'expected_operands': ['r1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'BX LR (return)',
        'instruction': 0xe12fff1e,  # bx lr
        'address': 0x1000,
        'expected_mnemonic': 'bx',
        'expected_operands': ['lr'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'BLX register',
        'instruction': 0xe12fff31,  # blx r1
        'address': 0x1000,
        'expected_mnemonic': 'blx',
        'expected_operands': ['r1'],
        'expected_info': {'length': 4},
    },

    # Note: BLX immediate (0xFA...) uses unconditional encoding which
    # requires special handling in the test framework
]


@pytest.mark.parametrize("case", BRANCH_TESTS, ids=lambda c: c["name"])
@pytest.mark.requires_binaryninja
def test_branch_cases(case, armv5_arch):
    assert_instruction_case(armv5_arch, case)
