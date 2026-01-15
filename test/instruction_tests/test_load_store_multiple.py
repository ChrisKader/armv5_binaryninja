"""Tests for ARM load/store multiple instructions."""
from __future__ import annotations

import pytest

from test.helpers import assert_instruction_case


LOAD_STORE_MULTIPLE_TESTS = [
    {
        "name": "STMIA basic - store r0,r1,r2,r3 to [r1]",
        "instruction": 0xE881000F,
        "address": 0x1000,
        "expected_mnemonic": "stmia",
        "expected_operands": ["r1", "{r0, r1, r2, r3}"],
        "expected_info": {"length": 4},
    },
    {
        "name": "LDMIA basic - load r0,r1,r2,r3 from [r1]",
        "instruction": 0xE891000F,
        "address": 0x1000,
        "expected_mnemonic": "ldmia",
        "expected_operands": ["r1", "{r0, r1, r2, r3}"],
        "expected_info": {"length": 4},
    },
    {
        "name": "STMIA writeback - store with base update",
        "instruction": 0xE8A1000F,
        "address": 0x1000,
        "expected_mnemonic": "stmia",
        "expected_operands": ["r1!", "{r0, r1, r2, r3}"],
        "expected_info": {"length": 4},
    },
    {
        "name": "LDMIA writeback - load with base update",
        "instruction": 0xE8B1000F,
        "address": 0x1000,
        "expected_mnemonic": "ldmia",
        "expected_operands": ["r1!", "{r0, r1, r2, r3}"],
        "expected_info": {"length": 4},
    },
    {
        "name": "STMFD stack push - typical function prologue",
        "instruction": 0xE92D500F,
        "address": 0x1000,
        "expected_mnemonic": "push",
        "expected_operands": ["{r0, r1, r2, r3, r12, lr}"],
        "expected_info": {"length": 4},
    },
    {
        "name": "LDMFD stack pop - typical function epilogue",
        "instruction": 0xE8BD500F,
        "address": 0x1000,
        "expected_mnemonic": "pop",
        "expected_operands": ["{r0, r1, r2, r3, r12, lr}"],
        "expected_info": {"length": 4},
    },
    {
        "name": "LDMFD with PC - function return",
        "instruction": 0xE8BD8000,
        "address": 0x1000,
        "expected_mnemonic": "pop",
        "expected_operands": ["{pc}"],
        "expected_info": {
            "length": 4,
            "arch_transition_by_target_addr": True,
            "branches": [{"type": "FunctionReturn"}],
        },
    },
    {
        "name": "STMIB increment before",
        "instruction": 0xE9810007,
        "address": 0x1000,
        "expected_mnemonic": "stmib",
        "expected_operands": ["r1", "{r0, r1, r2}"],
        "expected_info": {"length": 4},
    },
    {
        "name": "LDMDA decrement after",
        "instruction": 0xE811000F,
        "address": 0x1000,
        "expected_mnemonic": "ldmda",
        "expected_operands": ["r1", "{r0, r1, r2, r3}"],
        "expected_info": {"length": 4},
    },
    {
        "name": "STMDB decrement before",
        "instruction": 0xE901001F,
        "address": 0x1000,
        "expected_mnemonic": "stmdb",
        "expected_operands": ["r1", "{r0, r1, r2, r3, r4}"],
        "expected_info": {"length": 4},
    },
    {
        "name": "STMIA conditional - EQ",
        "instruction": 0x0881000F,
        "address": 0x1000,
        "expected_mnemonic": "stmiaeq",
        "expected_operands": ["r1", "{r0, r1, r2, r3}"],
        "expected_info": {"length": 4},
    },
    {
        "name": "STMIA user mode registers",
        "instruction": 0xE8C1000F,
        "address": 0x1000,
        "expected_mnemonic": "stmia",
        "expected_operands": ["r1", "{r0, r1, r2, r3} ^"],  # Note: space before ^
        "expected_info": {"length": 4},
    },
]


@pytest.mark.parametrize("case", LOAD_STORE_MULTIPLE_TESTS, ids=lambda c: c["name"])
@pytest.mark.requires_binaryninja
def test_load_store_multiple_cases(case, armv5_arch):
    assert_instruction_case(armv5_arch, case)
