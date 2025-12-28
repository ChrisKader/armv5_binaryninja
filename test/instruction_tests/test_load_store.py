"""Tests for ARM load/store instructions."""
from __future__ import annotations

import pytest

from test.helpers import assert_instruction_case


LOAD_STORE_TESTS = [
    # Basic LDR instructions
    {
        'name': 'LDR zero offset',
        'instruction': 0xe5910000,  # ldr r0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDR immediate offset - positive',
        'instruction': 0xe5910004,  # ldr r0, [r1, #4]
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDR immediate offset - negative',
        'instruction': 0xe5110004,  # ldr r0, [r1, #-4]
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1, #-0x4]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDR register offset',
        'instruction': 0xe7910002,  # ldr r0, [r1, r2]
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1, r2]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDR register offset with LSL shift',
        'instruction': 0xe7910102,  # ldr r0, [r1, r2, lsl #2]
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1, r2, lsl #0x2]'],
        'expected_info': {'length': 4},
    },

    # Basic STR instructions
    {
        'name': 'STR zero offset',
        'instruction': 0xe5810000,  # str r0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'str',
        'expected_operands': ['r0', '[r1]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STR immediate offset - positive',
        'instruction': 0xe5810004,  # str r0, [r1, #4]
        'address': 0x1000,
        'expected_mnemonic': 'str',
        'expected_operands': ['r0', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STR immediate offset - negative',
        'instruction': 0xe5010004,  # str r0, [r1, #-4]
        'address': 0x1000,
        'expected_mnemonic': 'str',
        'expected_operands': ['r0', '[r1, #-0x4]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STR register offset',
        'instruction': 0xe7810002,  # str r0, [r1, r2]
        'address': 0x1000,
        'expected_mnemonic': 'str',
        'expected_operands': ['r0', '[r1, r2]'],
        'expected_info': {'length': 4},
    },

    # Byte operations
    {
        'name': 'LDRB zero offset',
        'instruction': 0xe5d10000,  # ldrb r0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'ldrb',
        'expected_operands': ['r0', '[r1]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDRB immediate offset',
        'instruction': 0xe5d10004,  # ldrb r0, [r1, #4]
        'address': 0x1000,
        'expected_mnemonic': 'ldrb',
        'expected_operands': ['r0', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STRB zero offset',
        'instruction': 0xe5c10000,  # strb r0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'strb',
        'expected_operands': ['r0', '[r1]'],
        'expected_info': {'length': 4},
    },

    # Halfword operations
    {
        'name': 'LDRH zero offset',
        'instruction': 0xe1d100b0,  # ldrh r0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'ldrh',
        'expected_operands': ['r0', '[r1]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDRH immediate offset',
        'instruction': 0xe1d100b4,  # ldrh r0, [r1, #4]
        'address': 0x1000,
        'expected_mnemonic': 'ldrh',
        'expected_operands': ['r0', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STRH zero offset',
        'instruction': 0xe1c100b0,  # strh r0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'strh',
        'expected_operands': ['r0', '[r1]'],
        'expected_info': {'length': 4},
    },

    # Signed halfword/byte operations
    {
        'name': 'LDRSB zero offset',
        'instruction': 0xe1d100d0,  # ldrsb r0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'ldrsb',
        'expected_operands': ['r0', '[r1]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'LDRSH zero offset',
        'instruction': 0xe1d100f0,  # ldrsh r0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'ldrsh',
        'expected_operands': ['r0', '[r1]'],
        'expected_info': {'length': 4},
    },

    # Doubleword operations (ARMv5TE)
    {
        'name': 'LDRD zero offset',
        'instruction': 0xe1c100d0,  # ldrd r0, r1, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'ldrd',
        'expected_operands': ['r0', 'r1', '[r1]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STRD zero offset',
        'instruction': 0xe1c100f0,  # strd r0, r1, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'strd',
        'expected_operands': ['r0', 'r1', '[r1]'],
        'expected_info': {'length': 4},
    },

    # Pre-indexed with writeback - TODO: fix disassembler to show !
    {
        'name': 'LDR pre-indexed with writeback',
        'instruction': 0xe5b10004,  # ldr r0, [r1, #4]!
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STR pre-indexed with writeback',
        'instruction': 0xe5a10004,  # str r0, [r1, #4]!
        'address': 0x1000,
        'expected_mnemonic': 'str',
        'expected_operands': ['r0', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },

    # Post-indexed - TODO: fix operand parsing for post-indexed format
    {
        'name': 'LDR post-indexed',
        'instruction': 0xe4910004,  # ldr r0, [r1], #4
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[r1]', ', #0x4'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STR post-indexed',
        'instruction': 0xe4810004,  # str r0, [r1], #4
        'address': 0x1000,
        'expected_mnemonic': 'str',
        'expected_operands': ['r0', '[r1]', ', #0x4'],
        'expected_info': {'length': 4},
    },

    # Conditional load/store
    {
        'name': 'LDR conditional - EQ',
        'instruction': 0x05910004,  # ldreq r0, [r1, #4]
        'address': 0x1000,
        'expected_mnemonic': 'ldreq',
        'expected_operands': ['r0', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STR conditional - NE',
        'instruction': 0x15810004,  # strne r0, [r1, #4]
        'address': 0x1000,
        'expected_mnemonic': 'strne',
        'expected_operands': ['r0', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },

    # Special register usage
    {
        'name': 'LDR with SP as base',
        'instruction': 0xe59d0004,  # ldr r0, [sp, #4]
        'address': 0x1000,
        'expected_mnemonic': 'ldr',
        'expected_operands': ['r0', '[sp, #0x4]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'STR with LR as source',
        'instruction': 0xe581e004,  # str lr, [r1, #4]
        'address': 0x1000,
        'expected_mnemonic': 'str',
        'expected_operands': ['lr', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },
]


@pytest.mark.parametrize("case", LOAD_STORE_TESTS, ids=lambda c: c["name"])
@pytest.mark.requires_binaryninja
def test_load_store_cases(case, armv5_arch):
    assert_instruction_case(armv5_arch, case)
