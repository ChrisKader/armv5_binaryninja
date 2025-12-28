"""Tests for IsLikelyData pattern detection.

These tests verify that various invalid instruction patterns are correctly
identified as likely data, preventing incorrect disassembly.

Note: We test the raw disassembler behavior rather than Binary Ninja analysis
to avoid complex interactions with function analysis.
"""
from __future__ import annotations

import pytest


# Test cases that should decode successfully (valid instructions)
VALID_INSTRUCTION_PATTERNS = [
    # Valid multiply instructions
    (0xe0000192, 'MUL r0, r2, r1'),
    (0xe0203192, 'MLA r0, r2, r1, r3'),
    # UMULL/SMULL: RdLo and RdHi must be different registers
    (0xe0810392, 'UMULL r0, r1, r2, r3'),
    (0xe0c10392, 'SMULL r0, r1, r2, r3'),

    # Valid DSP multiplies
    (0xe1600182, 'SMULBB r0, r2, r1'),

    # Valid saturating arithmetic
    (0xe1010052, 'QADD r0, r2, r1'),
    (0xe1210052, 'QSUB r0, r2, r1'),

    # Valid coprocessor instructions (p14, p15)
    (0xee010f10, 'MCR p15, 0, r0, c1, c0, 0'),
    (0xee110f10, 'MRC p15, 0, r0, c1, c0, 0'),

    # Valid data processing
    (0xe0820001, 'ADD r0, r2, r1'),
    (0xe0420001, 'SUB r0, r2, r1'),
    (0xe1a00001, 'MOV r0, r1'),

    # Valid branches
    (0xeafffffe, 'B self'),
    (0xe12fff11, 'BX r1'),

    # Valid PLD (condition 0xF)
    (0xf5d1f000, 'PLD [r1]'),
]


@pytest.mark.parametrize("instr,description", VALID_INSTRUCTION_PATTERNS)
@pytest.mark.requires_binaryninja
def test_valid_instructions_decode(instr, description, armv5_arch):
    """Test that valid instructions decode successfully."""
    instr_bytes = instr.to_bytes(4, byteorder='little')
    address = 0x1000

    info = armv5_arch.get_instruction_info(instr_bytes, address)
    assert info is not None, f"Expected '{description}' to have instruction info"
    assert info.length == 4, f"Expected '{description}' to have length 4"

    text_tokens, length = armv5_arch.get_instruction_text(instr_bytes, address)
    assert length == 4, f"Expected '{description}' to have text length 4"
    assert text_tokens is not None, f"Expected '{description}' to have text tokens"
