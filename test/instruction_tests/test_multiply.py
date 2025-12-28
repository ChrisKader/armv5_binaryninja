"""Tests for ARM multiply and multiply-accumulate instructions."""
from __future__ import annotations

import pytest

from test.helpers import assert_instruction_case


MULTIPLY_TESTS = [
    # Basic MUL instructions
    {
        'name': 'MUL basic - r0 = r1 * r2',
        'instruction': 0xe0000291,  # mul r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'mul',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MULS with flags - r0 = r1 * r2',
        'instruction': 0xe0100291,  # muls r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'mul',  # Note: disassembler doesn't show S suffix
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # MLA instructions (multiply-accumulate)
    {
        'name': 'MLA basic - r0 = r1 * r2 + r3',
        'instruction': 0xe0203291,  # mla r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'mla',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MLAS with flags',
        'instruction': 0xe0303291,  # mlas r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'mla',  # Note: disassembler doesn't show S suffix
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },

    # Long multiply - unsigned
    {
        'name': 'UMULL - unsigned long multiply',
        'instruction': 0xe0810392,  # umull r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'umull',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'UMLAL - unsigned long multiply-accumulate',
        'instruction': 0xe0a10392,  # umlal r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'umlal',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },

    # Long multiply - signed
    {
        'name': 'SMULL - signed long multiply',
        'instruction': 0xe0c10392,  # smull r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smull',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMLAL - signed long multiply-accumulate',
        'instruction': 0xe0e10392,  # smlal r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlal',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },

    # Conditional multiply
    {
        'name': 'MUL conditional - EQ',
        'instruction': 0x00000291,  # muleq r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'muleq',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # DSP Multiply (ARMv5TE) - 16x16 -> 32
    {
        'name': 'SMULBB - signed multiply bottom x bottom',
        'instruction': 0xe1600281,  # smulbb r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'smulbb',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMULBT - signed multiply bottom x top',
        'instruction': 0xe16002c1,  # smulbt r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'smulbt',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMULTB - signed multiply top x bottom',
        'instruction': 0xe16002a1,  # smultb r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'smultb',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMULTT - signed multiply top x top',
        'instruction': 0xe16002e1,  # smultt r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'smultt',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # DSP Multiply (ARMv5TE) - 32x16 -> 32
    {
        'name': 'SMULWB - signed multiply word by bottom half',
        'instruction': 0xe12002a1,  # smulwb r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'smulwb',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMULWT - signed multiply word by top half',
        'instruction': 0xe12002e1,  # smulwt r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'smulwt',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # DSP Multiply-Accumulate (ARMv5TE)
    {
        'name': 'SMLABB - signed multiply-accumulate bottom x bottom',
        'instruction': 0xe1003281,  # smlabb r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlabb',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMLABT - signed multiply-accumulate bottom x top',
        'instruction': 0xe10032c1,  # smlabt r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlabt',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMLATB - signed multiply-accumulate top x bottom',
        'instruction': 0xe10032a1,  # smlatb r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlatb',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMLATT - signed multiply-accumulate top x top',
        'instruction': 0xe10032e1,  # smlatt r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlatt',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },

    # DSP Multiply-Accumulate Word (ARMv5TE)
    {
        'name': 'SMLAWB - signed multiply-accumulate word by bottom half',
        'instruction': 0xe1203281,  # smlawb r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlawb',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMLAWT - signed multiply-accumulate word by top half',
        'instruction': 0xe12032c1,  # smlawt r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlawt',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },

    # DSP Long Multiply-Accumulate (ARMv5TE)
    {
        'name': 'SMLALBB - signed long multiply-accumulate bottom x bottom',
        'instruction': 0xe1410382,  # smlalbb r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlalbb',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMLALBT - signed long multiply-accumulate bottom x top',
        'instruction': 0xe14103c2,  # smlalbt r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlalbt',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMLALTB - signed long multiply-accumulate top x bottom',
        'instruction': 0xe14103a2,  # smlaltb r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlaltb',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SMLALTT - signed long multiply-accumulate top x top',
        'instruction': 0xe14103e2,  # smlaltt r0, r1, r2, r3
        'address': 0x1000,
        'expected_mnemonic': 'smlaltt',
        'expected_operands': ['r0', 'r1', 'r2', 'r3'],
        'expected_info': {'length': 4},
    },
]


@pytest.mark.parametrize("case", MULTIPLY_TESTS, ids=lambda c: c["name"])
@pytest.mark.requires_binaryninja
def test_multiply_cases(case, armv5_arch):
    assert_instruction_case(armv5_arch, case)
