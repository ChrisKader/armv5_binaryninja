"""Tests for Thumb mode instructions.

Tests 16-bit Thumb instruction encoding and disassembly.
"""
from __future__ import annotations

import pytest

from test.helpers import assert_instruction_case


def thumb_case(name, instruction, expected_mnemonic, expected_operands, address=0x1000):
    """Helper to create Thumb test cases with 2-byte length."""
    return {
        'name': name,
        'instruction': instruction,
        'address': address,
        'expected_mnemonic': expected_mnemonic,
        'expected_operands': expected_operands,
        'expected_info': {'length': 2},
    }


THUMB_TESTS = [
    # Data processing - register
    thumb_case('AND register', 0x4008, 'ands', ['r0', 'r1']),
    thumb_case('EOR register', 0x4048, 'eors', ['r0', 'r1']),
    thumb_case('ORR register', 0x4308, 'orrs', ['r0', 'r1']),
    thumb_case('BIC register', 0x4388, 'bics', ['r0', 'r1']),
    thumb_case('MVN register', 0x43c8, 'mvns', ['r0', 'r1']),

    # Arithmetic
    thumb_case('ADD register low', 0x1808, 'adds', ['r0', 'r1', 'r0']),
    thumb_case('SUB register low', 0x1a08, 'subs', ['r0', 'r1', 'r0']),
    thumb_case('ADD immediate 3-bit', 0x1c08, 'adds', ['r0', 'r1', '#0']),
    thumb_case('SUB immediate 3-bit', 0x1e08, 'subs', ['r0', 'r1', '#0']),
    thumb_case('ADD immediate 8-bit', 0x3001, 'adds', ['r0', '#1']),
    thumb_case('SUB immediate 8-bit', 0x3801, 'subs', ['r0', '#1']),

    # MOV immediate
    thumb_case('MOV immediate', 0x2001, 'movs', ['r0', '#1']),
    thumb_case('MOV immediate max', 0x20ff, 'movs', ['r0', '#0xff']),

    # CMP
    thumb_case('CMP register', 0x4288, 'cmp', ['r0', 'r1']),
    thumb_case('CMP immediate', 0x2801, 'cmp', ['r0', '#1']),

    # Shifts
    thumb_case('LSL immediate', 0x0048, 'lsls', ['r0', 'r1', '#1']),
    thumb_case('LSR immediate', 0x0848, 'lsrs', ['r0', 'r1', '#1']),
    thumb_case('ASR immediate', 0x1048, 'asrs', ['r0', 'r1', '#1']),
    thumb_case('LSL register', 0x4088, 'lsls', ['r0', 'r1']),
    thumb_case('LSR register', 0x40c8, 'lsrs', ['r0', 'r1']),
    thumb_case('ASR register', 0x4108, 'asrs', ['r0', 'r1']),
    thumb_case('ROR register', 0x41c8, 'rors', ['r0', 'r1']),

    # Multiply
    thumb_case('MUL register', 0x4348, 'muls', ['r0', 'r1', 'r0']),

    # Negate
    thumb_case('NEG/RSB', 0x4248, 'rsbs', ['r0', 'r1', '#0']),

    # ADC/SBC
    thumb_case('ADC register', 0x4148, 'adcs', ['r0', 'r1']),
    thumb_case('SBC register', 0x4188, 'sbcs', ['r0', 'r1']),

    # TST/CMN
    thumb_case('TST register', 0x4208, 'tst', ['r0', 'r1']),
    thumb_case('CMN register', 0x42c8, 'cmn', ['r0', 'r1']),

    # High register operations
    thumb_case('ADD high register', 0x4408, 'add', ['r0', 'r1']),
    thumb_case('CMP high register', 0x4548, 'cmp', ['r0', 'r9']),
    thumb_case('MOV high register', 0x4608, 'mov', ['r0', 'r1']),

    # Branch and exchange
    thumb_case('BX register', 0x4708, 'bx', ['r1']),
    thumb_case('BX LR', 0x4770, 'bx', ['lr']),
    thumb_case('BLX register', 0x4788, 'blx', ['r1']),

    # Load/Store word
    thumb_case('LDR register offset', 0x5808, 'ldr', ['r0', '[r1, r0]']),
    thumb_case('STR register offset', 0x5008, 'str', ['r0', '[r1, r0]']),
    thumb_case('LDR immediate offset', 0x6808, 'ldr', ['r0', '[r1]']),
    thumb_case('STR immediate offset', 0x6008, 'str', ['r0', '[r1]']),
    thumb_case('LDR SP relative', 0x9800, 'ldr', ['r0', '[sp]']),
    thumb_case('STR SP relative', 0x9000, 'str', ['r0', '[sp]']),
    thumb_case('LDR PC relative', 0x4800, 'ldr', ['r0', '[pc']),  # Partial match

    # Load/Store byte
    thumb_case('LDRB register offset', 0x5c08, 'ldrb', ['r0', '[r1, r0]']),
    thumb_case('STRB register offset', 0x5408, 'strb', ['r0', '[r1, r0]']),
    thumb_case('LDRB immediate offset', 0x7808, 'ldrb', ['r0', '[r1]']),
    thumb_case('STRB immediate offset', 0x7008, 'strb', ['r0', '[r1]']),

    # Load/Store halfword
    thumb_case('LDRH register offset', 0x5a08, 'ldrh', ['r0', '[r1, r0]']),
    thumb_case('STRH register offset', 0x5208, 'strh', ['r0', '[r1, r0]']),
    thumb_case('LDRH immediate offset', 0x8808, 'ldrh', ['r0', '[r1]']),
    thumb_case('STRH immediate offset', 0x8008, 'strh', ['r0', '[r1]']),

    # Signed load
    thumb_case('LDRSB register offset', 0x5608, 'ldrsb', ['r0', '[r1, r0]']),
    thumb_case('LDRSH register offset', 0x5e08, 'ldrsh', ['r0', '[r1, r0]']),

    # Load/Store multiple - use 'ldm'/'stm' mnemonic (actual output)
    thumb_case('LDMIA basic', 0xc901, 'ldm', ['r1!', '{r0}']),
    thumb_case('STMIA basic', 0xc101, 'stm', ['r1!', '{r0}']),

    # PUSH/POP
    thumb_case('PUSH registers', 0xb501, 'push', ['{r0, lr}']),
    thumb_case('POP registers', 0xbd01, 'pop', ['{r0, pc}']),
    thumb_case('PUSH multiple', 0xb50f, 'push', ['{r0, r1, r2, r3, lr}']),
    thumb_case('POP multiple', 0xbd0f, 'pop', ['{r0, r1, r2, r3, pc}']),

    # SP adjust
    thumb_case('ADD SP immediate', 0xb001, 'add', ['sp', '#4']),
    thumb_case('SUB SP immediate', 0xb081, 'sub', ['sp', '#4']),

    # ADR (add PC) - actual output shows adr with computed value
    thumb_case('ADR/ADD PC', 0xa001, 'adr', ['r0', '#4']),

    # ADD SP to register
    thumb_case('ADD SP to register', 0xa801, 'add', ['r0', 'sp', '#4']),

    # Conditional branches - use CS/CC synonyms
    thumb_case('BEQ', 0xd000, 'beq', ['0x1004']),
    thumb_case('BNE', 0xd100, 'bne', ['0x1004']),
    thumb_case('BCS', 0xd200, 'bcs', ['0x1004']),  # CS instead of HS
    thumb_case('BCC', 0xd300, 'bcc', ['0x1004']),  # CC instead of LO
    thumb_case('BMI', 0xd400, 'bmi', ['0x1004']),
    thumb_case('BPL', 0xd500, 'bpl', ['0x1004']),
    thumb_case('BVS', 0xd600, 'bvs', ['0x1004']),
    thumb_case('BVC', 0xd700, 'bvc', ['0x1004']),
    thumb_case('BHI', 0xd800, 'bhi', ['0x1004']),
    thumb_case('BLS', 0xd900, 'bls', ['0x1004']),
    thumb_case('BGE', 0xda00, 'bge', ['0x1004']),
    thumb_case('BLT', 0xdb00, 'blt', ['0x1004']),
    thumb_case('BGT', 0xdc00, 'bgt', ['0x1004']),
    thumb_case('BLE', 0xdd00, 'ble', ['0x1004']),

    # Unconditional branch
    thumb_case('B unconditional', 0xe000, 'b', ['0x1004']),

    # SVC (software interrupt)
    thumb_case('SVC', 0xdf00, 'svc', ['#0']),
    thumb_case('SVC with immediate', 0xdf10, 'svc', ['#0x10']),

    # BKPT
    thumb_case('BKPT', 0xbe00, 'bkpt', ['#0']),
    thumb_case('BKPT with immediate', 0xbe10, 'bkpt', ['#0x10']),

    # NOP (mov r8, r8) - shows as mov instruction
    thumb_case('NOP', 0x46c0, 'mov', ['r0', 'r8']),
]


# 32-bit Thumb instructions (BL/BLX immediate use two consecutive halfwords)
def thumb32_case(name, instruction, expected_mnemonic, expected_operands, address=0x1000):
    """Helper to create 32-bit Thumb test cases with 4-byte length."""
    return {
        'name': name,
        'instruction': instruction,
        'address': address,
        'expected_mnemonic': expected_mnemonic,
        'expected_operands': expected_operands,
        'expected_info': {'length': 4},
    }


THUMB32_TESTS = [
    # BL (Branch with Link) - 32-bit instruction
    # Encoding: 11110 S imm10 11 J1 1 J2 imm11
    # bl +0x10 from 0x1000 = target 0x1014
    # imm32 = 0x10, S=0, I1=1, I2=1, imm10=0, imm11=0x8
    # First halfword: 11110 0 0000000000 = 0xF000
    # Second halfword: 11 1 1 1 00000001000 = 0xF808
    # Combined: 0xF000F808
    thumb32_case('BL forward', 0xF000F808, 'bl', ['#0x1014']),
]


@pytest.mark.parametrize("case", THUMB32_TESTS, ids=lambda c: c["name"])
@pytest.mark.requires_binaryninja
def test_thumb32_cases(case, thumb_arch):
    """Test 32-bit Thumb instruction disassembly (BL/BLX)."""
    # For 32-bit Thumb, instruction is two 16-bit halfwords in little-endian
    instruction_value = case['instruction']
    # Split into two halfwords: high 16 bits are first halfword, low 16 bits are second
    hw1 = (instruction_value >> 16) & 0xFFFF
    hw2 = instruction_value & 0xFFFF
    # Encode as little-endian (each halfword separately)
    instr_bytes = hw1.to_bytes(2, byteorder='little') + hw2.to_bytes(2, byteorder='little')
    address = case.get('address', 0)

    info = thumb_arch.get_instruction_info(instr_bytes, address)
    assert info is not None, f"Instruction info not available for {case['name']}"
    assert info.length == 4, f"Expected length 4, got {info.length} for {case['name']}"

    text_tokens, length = thumb_arch.get_instruction_text(instr_bytes, address)
    assert length == 4, f"Text length mismatch for {case['name']}"

    instruction_text = ''.join(token.text for token in text_tokens).strip()
    parts = instruction_text.split(maxsplit=1)
    assert parts, f"No disassembly text for {case['name']}"

    actual_mnemonic = parts[0]
    expected_mnemonic = case['expected_mnemonic']
    assert actual_mnemonic == expected_mnemonic, \
        f"Mnemonic mismatch for {case['name']}: expected '{expected_mnemonic}', got '{actual_mnemonic}'"

    if len(parts) > 1 and case['expected_operands']:
        actual_operands = [op.strip() for op in parts[1].split(',')]
        expected_operands = case['expected_operands']
        assert actual_operands == expected_operands, \
            f"Operands mismatch for {case['name']}: expected {expected_operands}, got {actual_operands}"


@pytest.mark.parametrize("case", THUMB_TESTS, ids=lambda c: c["name"])
@pytest.mark.requires_binaryninja
def test_thumb_cases(case, thumb_arch):
    """Test Thumb instruction disassembly."""
    # For Thumb, instruction is 16-bit, convert to 2-byte little-endian
    instruction_value = case['instruction']
    instr_bytes = instruction_value.to_bytes(2, byteorder='little')
    address = case.get('address', 0)

    info = thumb_arch.get_instruction_info(instr_bytes, address)
    assert info is not None, f"Instruction info not available for {case['name']}"
    assert info.length == 2, f"Expected length 2, got {info.length} for {case['name']}"

    text_tokens, length = thumb_arch.get_instruction_text(instr_bytes, address)
    assert length == 2, f"Text length mismatch for {case['name']}"

    instruction_text = ''.join(token.text for token in text_tokens).strip()
    parts = instruction_text.split(maxsplit=1)
    assert parts, f"No disassembly text for {case['name']}"

    actual_mnemonic = parts[0]
    expected_mnemonic = case['expected_mnemonic']
    assert actual_mnemonic == expected_mnemonic, (
        f"Expected mnemonic '{expected_mnemonic}', got '{actual_mnemonic}' in '{instruction_text}'"
    )

    # Optional: check operands if specified
    expected_operands = case.get('expected_operands', [])
    if expected_operands and len(parts) > 1:
        # Simple operand check - just verify they appear in the output
        operands_text = parts[1]
        for op in expected_operands:
            assert op in operands_text or op.replace('#', '') in operands_text, (
                f"Expected operand '{op}' not found in '{operands_text}' for {case['name']}"
            )
