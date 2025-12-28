"""Tests for VFP (Vector Floating Point) instructions."""
from __future__ import annotations

import pytest

from test.helpers import assert_instruction_case


VFP_TESTS = [
    # Note: VFP disassembler output doesn't include .f32 suffix

    # VADD
    {
        'name': 'VADD',
        'instruction': 0xee300a01,  # vadd s0, s0, s2
        'address': 0x1000,
        'expected_mnemonic': 'vadd',
        'expected_operands': ['s0', 's0', 's2'],
        'expected_info': {'length': 4},
    },

    # VSUB
    {
        'name': 'VSUB',
        'instruction': 0xee300a41,  # vsub s0, s0, s2
        'address': 0x1000,
        'expected_mnemonic': 'vsub',
        'expected_operands': ['s0', 's0', 's2'],
        'expected_info': {'length': 4},
    },

    # VMUL
    {
        'name': 'VMUL',
        'instruction': 0xee200a01,  # vmul s0, s0, s2
        'address': 0x1000,
        'expected_mnemonic': 'vmul',
        'expected_operands': ['s0', 's0', 's2'],
        'expected_info': {'length': 4},
    },

    # VDIV
    {
        'name': 'VDIV',
        'instruction': 0xee800a01,  # vdiv s0, s0, s2
        'address': 0x1000,
        'expected_mnemonic': 'vdiv',
        'expected_operands': ['s0', 's0', 's2'],
        'expected_info': {'length': 4},
    },

    # VLDR
    {
        'name': 'VLDR',
        'instruction': 0xed910a00,  # vldr s0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'vldr',
        'expected_operands': ['s0', '[r1]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'VLDR with offset',
        'instruction': 0xed910a01,  # vldr s0, [r1, #4]
        'address': 0x1000,
        'expected_mnemonic': 'vldr',
        'expected_operands': ['s0', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },

    # VSTR
    {
        'name': 'VSTR',
        'instruction': 0xed810a00,  # vstr s0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'vstr',
        'expected_operands': ['s0', '[r1]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'VSTR with offset',
        'instruction': 0xed810a01,  # vstr s0, [r1, #4]
        'address': 0x1000,
        'expected_mnemonic': 'vstr',
        'expected_operands': ['s0', '[r1, #0x4]'],
        'expected_info': {'length': 4},
    },

    # VABS
    {
        'name': 'VABS',
        'instruction': 0xeeb00ac1,  # vabs s0, s2
        'address': 0x1000,
        'expected_mnemonic': 'vabs',
        'expected_operands': ['s0', 's2'],
        'expected_info': {'length': 4},
    },

    # VMLA (multiply-accumulate)
    {
        'name': 'VMLA',
        'instruction': 0xee000a01,  # vmla s0, s0, s2
        'address': 0x1000,
        'expected_mnemonic': 'vmla',
        'expected_operands': ['s0', 's0', 's2'],
        'expected_info': {'length': 4},
    },

    # VMLS (multiply-subtract)
    {
        'name': 'VMLS',
        'instruction': 0xee000a41,  # vmls s0, s0, s2
        'address': 0x1000,
        'expected_mnemonic': 'vmls',
        'expected_operands': ['s0', 's0', 's2'],
        'expected_info': {'length': 4},
    },

    # VNMUL (negated multiply)
    {
        'name': 'VNMUL',
        'instruction': 0xee200a41,  # vnmul s0, s0, s2
        'address': 0x1000,
        'expected_mnemonic': 'vnmul',
        'expected_operands': ['s0', 's0', 's2'],
        'expected_info': {'length': 4},
    },

    # Double-precision operations
    {
        'name': 'VADD double',
        'instruction': 0xee300b01,  # vadd d0, d0, d1
        'address': 0x1000,
        'expected_mnemonic': 'vadd',
        'expected_operands': ['d0', 'd0', 'd1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'VLDR double',
        'instruction': 0xed910b00,  # vldr d0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'vldr',
        'expected_operands': ['d0', '[r1]'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'VSTR double',
        'instruction': 0xed810b00,  # vstr d0, [r1]
        'address': 0x1000,
        'expected_mnemonic': 'vstr',
        'expected_operands': ['d0', '[r1]'],
        'expected_info': {'length': 4},
    },

    # Conditional VFP
    {
        'name': 'VADD conditional - EQ',
        'instruction': 0x0e300a01,  # vaddeq s0, s0, s2
        'address': 0x1000,
        'expected_mnemonic': 'vaddeq',
        'expected_operands': ['s0', 's0', 's2'],
        'expected_info': {'length': 4},
    },

    # VNEG
    {
        'name': 'VNEG single',
        'instruction': 0xeeb10a01,  # vneg.f32 s0, s2
        'address': 0x1000,
        'expected_mnemonic': 'vneg',
        'expected_operands': ['s0', 's2'],
        'expected_info': {'length': 4},
    },

    # VCVT (float to int)
    {
        'name': 'VCVT F32 to S32',
        'instruction': 0xeebd0ac0,  # vcvt.s32.f32 s0, s0
        'address': 0x1000,
        'expected_mnemonic': 'vcvt',
        'expected_operands': ['s0', 's0'],
        'expected_info': {'length': 4},
    },

    # VMOV ARM to VFP
    {
        'name': 'VMOV ARM to VFP single',
        'instruction': 0xee000a10,  # vmov s0, r0
        'address': 0x1000,
        'expected_mnemonic': 'vmov',
        'expected_operands': ['s0', 'r0'],
        'expected_info': {'length': 4},
    },

    # VMOV VFP to ARM
    {
        'name': 'VMOV VFP single to ARM',
        'instruction': 0xee100a10,  # vmov r0, s0
        'address': 0x1000,
        'expected_mnemonic': 'vmov',
        'expected_operands': ['r0', 's0'],
        'expected_info': {'length': 4},
    },

    # VMRS - VFP to ARM status
    {
        'name': 'VMRS FPSCR to ARM',
        'instruction': 0xeef10a10,  # vmrs r0, fpscr
        'address': 0x1000,
        'expected_mnemonic': 'vmrs',
        'expected_operands': ['r0', 'fpscr'],
        'expected_info': {'length': 4},
    },

    # FMSTAT (VMRS APSR_nzcv, FPSCR)
    {
        'name': 'FMSTAT',
        'instruction': 0xeef1fa10,  # fmstat (vmrs APSR_nzcv, fpscr)
        'address': 0x1000,
        'expected_mnemonic': 'fmstat',
        'expected_operands': [],
        'expected_info': {'length': 4},
    },

    # VMSR - ARM to VFP status
    {
        'name': 'VMSR ARM to FPSCR',
        'instruction': 0xeee10a10,  # vmsr fpscr, r0
        'address': 0x1000,
        'expected_mnemonic': 'vmsr',
        'expected_operands': ['fpscr', 'r0'],
        'expected_info': {'length': 4},
    },

    # VCMP with zero (uses FIMM operand)
    {
        'name': 'VCMP with zero',
        'instruction': 0xeeb40a40,  # vcmp.f32 s0, #0.0
        'address': 0x1000,
        'expected_mnemonic': 'vcmp',
        'expected_operands': ['s0', '#0.0'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'VCMPE with zero',
        'instruction': 0xeeb50a40,  # vcmpe.f32 s0, #0.0
        'address': 0x1000,
        'expected_mnemonic': 'vcmpe',
        'expected_operands': ['s0', '#0.0'],
        'expected_info': {'length': 4},
    },
]


@pytest.mark.parametrize("case", VFP_TESTS, ids=lambda c: c["name"])
@pytest.mark.requires_binaryninja
def test_vfp_cases(case, armv5_arch):
    assert_instruction_case(armv5_arch, case)
