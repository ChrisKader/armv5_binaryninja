"""Tests for ARM data processing instructions."""
from __future__ import annotations

import pytest

from test.helpers import assert_instruction_case


# Test data format for instruction tests
DATA_PROCESSING_TESTS = [
    # AND instructions
    {
        'name': 'AND immediate - basic',
        'instruction': 0xe2001001,  # and r1, r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'and',
        'expected_operands': ['r1', 'r0', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'AND immediate with flags',
        'instruction': 0xe2111001,  # ands r1, r1, #1
        'address': 0x1000,
        'expected_mnemonic': 'ands',
        'expected_operands': ['r1', 'r1', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'AND register - basic',
        'instruction': 0xe0001002,  # and r1, r0, r2
        'address': 0x1000,
        'expected_mnemonic': 'and',
        'expected_operands': ['r1', 'r0', 'r2'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'AND register with LSL shift',
        'instruction': 0xe0001102,  # and r1, r0, r2, lsl #2
        'address': 0x1000,
        'expected_mnemonic': 'and',
        'expected_operands': ['r1', 'r0', 'r2', 'lsl #0x2'],
        'expected_info': {'length': 4},
    },

    # EOR instructions
    {
        'name': 'EOR immediate',
        'instruction': 0xe2201001,  # eor r1, r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'eor',
        'expected_operands': ['r1', 'r0', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'EOR register',
        'instruction': 0xe0210002,  # eor r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'eor',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # SUB instructions
    {
        'name': 'SUB immediate',
        'instruction': 0xe2401001,  # sub r1, r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'sub',
        'expected_operands': ['r1', 'r0', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SUB register',
        'instruction': 0xe0401002,  # sub r1, r0, r2
        'address': 0x1000,
        'expected_mnemonic': 'sub',
        'expected_operands': ['r1', 'r0', 'r2'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'SUBS with flags',
        'instruction': 0xe0510002,  # subs r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'subs',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # RSB instructions
    {
        'name': 'RSB immediate',
        'instruction': 0xe2601001,  # rsb r1, r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'rsb',
        'expected_operands': ['r1', 'r0', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'RSB register',
        'instruction': 0xe0610002,  # rsb r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'rsb',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # ADD instructions
    {
        'name': 'ADD immediate',
        'instruction': 0xe2801001,  # add r1, r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'add',
        'expected_operands': ['r1', 'r0', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'ADD register',
        'instruction': 0xe0801002,  # add r1, r0, r2
        'address': 0x1000,
        'expected_mnemonic': 'add',
        'expected_operands': ['r1', 'r0', 'r2'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'ADDS with flags',
        'instruction': 0xe0910002,  # adds r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'adds',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # ADC instructions
    {
        'name': 'ADC register',
        'instruction': 0xe0a10002,  # adc r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'adc',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # SBC instructions
    {
        'name': 'SBC register',
        'instruction': 0xe0c10002,  # sbc r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'sbc',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # RSC instructions - Note: RSC is flagged as likely data by IsLikelyData
    # so we skip testing it here

    # ORR instructions
    {
        'name': 'ORR register',
        'instruction': 0xe1810002,  # orr r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'orr',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # BIC instructions
    {
        'name': 'BIC immediate',
        'instruction': 0xe3c01001,  # bic r1, r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'bic',
        'expected_operands': ['r1', 'r0', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'BIC register',
        'instruction': 0xe1c10002,  # bic r0, r1, r2
        'address': 0x1000,
        'expected_mnemonic': 'bic',
        'expected_operands': ['r0', 'r1', 'r2'],
        'expected_info': {'length': 4},
    },

    # MOV instructions
    {
        'name': 'MOV immediate - small value',
        'instruction': 0xe3a0002a,  # mov r0, #42
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r0', '#0x2a'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOV immediate - rotated value',
        'instruction': 0xe3a00c02,  # mov r0, #0x200
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r0', '#0x200'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOV register',
        'instruction': 0xe1a01000,  # mov r1, r0
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r1', 'r0'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOVS with flags',
        'instruction': 0xe1b01000,  # movs r1, r0
        'address': 0x1000,
        'expected_mnemonic': 'movs',
        'expected_operands': ['r1', 'r0'],
        'expected_info': {'length': 4},
    },

    # MVN instructions
    {
        'name': 'MVN immediate',
        'instruction': 0xe3e01001,  # mvn r1, #1
        'address': 0x1000,
        'expected_mnemonic': 'mvn',
        'expected_operands': ['r1', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MVN register',
        'instruction': 0xe1e01000,  # mvn r1, r0
        'address': 0x1000,
        'expected_mnemonic': 'mvn',
        'expected_operands': ['r1', 'r0'],
        'expected_info': {'length': 4},
    },

    # Comparison instructions (no destination register)
    {
        'name': 'CMP immediate',
        'instruction': 0xe3500001,  # cmp r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'cmp',
        'expected_operands': ['r0', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'CMP register',
        'instruction': 0xe1500001,  # cmp r0, r1
        'address': 0x1000,
        'expected_mnemonic': 'cmp',
        'expected_operands': ['r0', 'r1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'CMN immediate',
        'instruction': 0xe3700001,  # cmn r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'cmn',
        'expected_operands': ['r0', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'TST immediate',
        'instruction': 0xe3100001,  # tst r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'tst',
        'expected_operands': ['r0', '#0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'TEQ immediate',
        'instruction': 0xe3300001,  # teq r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'teq',
        'expected_operands': ['r0', '#0x1'],
        'expected_info': {'length': 4},
    },

    # Conditional instructions
    {
        'name': 'MOV conditional - EQ',
        'instruction': 0x03a00000,  # moveq r0, #0
        'address': 0x1000,
        'expected_mnemonic': 'moveq',
        'expected_operands': ['r0', '#0x0'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'ADD conditional - NE',
        'instruction': 0x12801001,  # addne r1, r0, #1
        'address': 0x1000,
        'expected_mnemonic': 'addne',
        'expected_operands': ['r1', 'r0', '#0x1'],
        'expected_info': {'length': 4},
    },

    # Register shifts
    {
        'name': 'MOV with LSL immediate shift',
        'instruction': 0xe1a01081,  # mov r1, r1, lsl #1
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r1', 'r1', 'lsl #0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOV with LSL register shift',
        'instruction': 0xe1a01310,  # mov r1, r0, lsl r3
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r1', 'r0', 'lsl r3'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOV with LSR immediate shift',
        'instruction': 0xe1a010a1,  # mov r1, r1, lsr #1
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r1', 'r1', 'lsr #0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOV with ASR immediate shift',
        'instruction': 0xe1a010c1,  # mov r1, r1, asr #1
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r1', 'r1', 'asr #0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOV with ROR immediate shift',
        'instruction': 0xe1a010e1,  # mov r1, r1, ror #1
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r1', 'r1', 'ror #0x1'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'MOV with RRX',
        'instruction': 0xe1a01061,  # mov r1, r1, rrx
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r1', 'r1', 'rrx #0x1'],
        'expected_info': {'length': 4},
    },

    # Special register usage
    {
        'name': 'MOV with PC source',
        'instruction': 0xe1a0000f,  # mov r0, pc
        'address': 0x1000,
        'expected_mnemonic': 'mov',
        'expected_operands': ['r0', 'pc'],
        'expected_info': {'length': 4},
    },
    {
        'name': 'ADD with SP',
        'instruction': 0xe28d1004,  # add r1, sp, #4
        'address': 0x1000,
        'expected_mnemonic': 'add',
        'expected_operands': ['r1', 'sp', '#0x4'],
        'expected_info': {'length': 4},
    },
]


@pytest.mark.parametrize("case", DATA_PROCESSING_TESTS, ids=lambda c: c["name"])
@pytest.mark.requires_binaryninja
def test_data_processing_cases(case, armv5_arch):
    assert_instruction_case(armv5_arch, case)
