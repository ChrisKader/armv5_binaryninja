"""Tests for LLIL lifting of ARM instructions."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


# Test cases: (instruction bytes, expected LLIL string)
LLIL_ARM_TESTS = [
    # Basic load/store with PC-relative addressing
    # ldr r0, [r1] -> r0 = load(r1)
    (b'\x00\x00\x91\xe5', 'LLIL_SET_REG(r0,LLIL_LOAD(LLIL_REG(r1)))'),
    # str r0, [r1] -> store(r1, r0)
    (b'\x00\x00\x81\xe5', 'LLIL_STORE(LLIL_REG(r1),LLIL_REG(r0))'),

    # Data processing
    # add r0, r2, r1 -> r0 = r2 + r1
    (b'\x01\x00\x82\xe0', 'LLIL_SET_REG(r0,LLIL_ADD(LLIL_REG(r2),LLIL_REG(r1)))'),
    # sub r0, r2, r1 -> r0 = r2 - r1
    (b'\x01\x00\x42\xe0', 'LLIL_SET_REG(r0,LLIL_SUB(LLIL_REG(r2),LLIL_REG(r1)))'),
    # and r0, r2, r1 -> r0 = r2 & r1
    (b'\x01\x00\x02\xe0', 'LLIL_SET_REG(r0,LLIL_AND(LLIL_REG(r2),LLIL_REG(r1)))'),
    # orr r0, r2, r1 -> r0 = r2 | r1
    (b'\x01\x00\x82\xe1', 'LLIL_SET_REG(r0,LLIL_OR(LLIL_REG(r2),LLIL_REG(r1)))'),
    # eor r0, r2, r1 -> r0 = r2 ^ r1
    (b'\x01\x00\x22\xe0', 'LLIL_SET_REG(r0,LLIL_XOR(LLIL_REG(r2),LLIL_REG(r1)))'),

    # Long multiply: umull r0, r1, r2, r3
    (b'\x92\x03\x81\xe0', 'LLIL_SET_REG_SPLIT(r1,r0,LLIL_MULU_DP(LLIL_REG(r2),LLIL_REG(r3)))'),
    # Long multiply: smull r0, r1, r2, r3
    (b'\x92\x03\xc1\xe0', 'LLIL_SET_REG_SPLIT(r1,r0,LLIL_MULS_DP(LLIL_REG(r2),LLIL_REG(r3)))'),

    # Multiply and accumulate: mla r0, r1, r2, r3 -> r0 = r3 + (r1 * r2)
    (b'\x91\x32\x20\xe0', 'LLIL_SET_REG(r0,LLIL_ADD(LLIL_REG(r3),LLIL_MUL(LLIL_REG(r1),LLIL_REG(r2))))'),

    # mov r0, r1 -> r0 = r1
    (b'\x01\x00\xa0\xe1', 'LLIL_SET_REG(r0,LLIL_REG(r1))'),
    # mov r0, #5 -> r0 = 5
    (b'\x05\x00\xa0\xe3', 'LLIL_SET_REG(r0,LLIL_CONST(5))'),

    # NOP (mov r0, r0) - optimized to empty by BN since we decode as ARMV5_NOP
    (b'\x00\x00\xa0\xe1', ''),

    # Branch instructions
    # bx lr -> return
    (b'\x1e\xff\x2f\xe1', 'LLIL_RET(LLIL_REG(lr))'),
    # bx r0 -> tailcall(r0)
    (b'\x10\xff\x2f\xe1', 'LLIL_TAILCALL(LLIL_REG(r0))'),
    # blx r0 -> call(r0)
    (b'\x30\xff\x2f\xe1', 'LLIL_CALL(LLIL_REG(r0))'),
]

# Instructions that should be rejected as likely data (IsLikelyData returns true)
# These produce empty IL because GetInstructionInfo returns false
LLIL_LIKELY_DATA_TESTS = [
    # Pattern 6b: Long multiply with S flag AND conditional execution
    # Literal pool pointers like 0x10bxxxxx decode as "umlalsne"
    # 0x10b82490: umlalsne r2, r8, r0, r4 - S flag + NE condition
    (b'\x90\x24\xb8\x10', ''),
    # 0x10b67290: umlalsne r7, r6, r0, r2 - S flag + NE condition
    (b'\x90\x72\xb6\x10', ''),
    # 0x10b5fd9c: umlalsne pc, r5, r12, sp - PC as RdLo, SP as Rs
    (b'\x9c\xfd\xb5\x10', ''),

    # Pattern: RSC is extremely rare
    # 0x00edb910: rsceq r11, sp, r0, lsl r9
    (b'\x10\xb9\xed\x00', ''),

    # Pattern 8: Coprocessor to unusual coprocessor (p9)
    # 0x4cecb910: stcmi p9, c11, [r12], #0x40
    (b'\x10\xb9\xec\x4c', ''),
    # 0x3cedb910: stclo p9, c11, [sp], #0x40
    (b'\x10\xb9\xed\x3c', ''),

    # Pattern 6b: SMULL with PC as source
    # 0x20d01f9f: smullshs r1, r0, pc, pc - PC as both Rm and Rs
    (b'\x9f\x1f\xd0\x20', ''),

    # Pattern 6b: SMLAL with LR as RdHi
    # 0x00fec19d: smlalseq r12, lr, sp, r1 - LR as RdHi, SP as Rm
    (b'\x9d\xc1\xfe\x00', ''),
]


def il2str(il):
    """Convert an LLIL instruction to a string representation."""
    from binaryninja import lowlevelil
    if isinstance(il, lowlevelil.LowLevelILInstruction):
        return '%s(%s)' % (il.operation.name, ','.join([il2str(o) for o in il.operands]))
    else:
        return str(il)


def instr_to_il(data, arch_name, binaryninja_module, expect_rejected=False):
    """Convert instruction bytes to LLIL string."""
    arch = binaryninja_module.Architecture[arch_name]
    plat = arch.standalone_platform

    sled = b''
    sled_len = 0x1000
    if arch_name == 'armv5t':
        sled = b'\xc0\x46' * (sled_len // 2)  # Thumb NOP (mov r8, r8)
    elif arch_name == 'armv5':
        sled = b'\x00\x00\xa0\xe1' * (sled_len // 4)  # ARM NOP (mov r0, r0)

    bv = binaryninja_module.binaryview.BinaryView.new(sled + data)
    bv.add_function(sled_len, plat=plat)

    # If instruction is rejected by GetInstructionInfo, no function is created
    # at that address, or function analysis stops at that point
    if len(bv.functions) == 0:
        return '' if expect_rejected else 'NO_FUNCTION'

    result = []
    for block in bv.functions[0].low_level_il:
        for il in block:
            result.append(il2str(il))
    result = '; '.join(result)

    # If instruction was rejected, we won't see LLIL_UNDEF at expected position
    if not result.endswith('LLIL_UNDEF()'):
        # The function stopped before reaching our instruction
        return '' if expect_rejected else result

    result = result[0:result.index('LLIL_UNDEF()')]
    if result.endswith('; '):
        result = result[0:-2]

    return result


@pytest.mark.parametrize("data,expected", LLIL_ARM_TESTS)
@pytest.mark.requires_binaryninja
def test_llil_arm(data, expected, binaryninja_module):
    """Test ARM mode LLIL lifting."""
    actual = instr_to_il(data, 'armv5', binaryninja_module)
    assert actual == expected, f"LLIL mismatch for {data.hex()}: expected '{expected}', got '{actual}'"


@pytest.mark.requires_binaryninja
def test_conditional_bx_sequence(binaryninja_module):
    """Test conditional BX with fallthrough - a known crash case for malformed LLIL.

    Code: CMP r0,#0; BXEQ lr; ADD r0,r0,#1; BX lr
    This forces a conditional early-return with fallthrough.

    The crash happens during CFG rebuilding when:
    - A conditional BX creates a block that "returns but also falls through"
    - BN tries to reanalyze and the malformed CFG causes infinite recursion

    This test explicitly triggers reanalysis to catch the crash.
    """
    # CMP r0,#0; BXEQ lr; ADD r0,r0,#1; BX lr
    code = bytes.fromhex('000050e3' '1eff2f01' '010080e2' '1eff2fe1')

    arch = binaryninja_module.Architecture['armv5']
    bv = binaryninja_module.binaryview.BinaryView.new(code)
    bv.add_function(0, plat=arch.standalone_platform)

    assert len(bv.functions) == 1, "Function should be created"
    func = bv.functions[0]

    # First analysis pass
    bv.update_analysis_and_wait()

    # Collect LLIL before reanalysis
    all_il_before = []
    for block in func.low_level_il:
        for il in block:
            all_il_before.append(str(il))

    # Force reanalysis - this is where malformed LLIL crashes
    func.reanalyze()
    bv.update_analysis_and_wait()

    # Collect LLIL after reanalysis
    all_il_after = []
    for block in func.low_level_il:
        for il in block:
            all_il_after.append(str(il))

    # Verify we have the expected structure:
    # - A conditional (if flag:z)
    # - Two return paths (conditional and unconditional)
    il_text = '; '.join(all_il_after)
    assert 'if (flag:z)' in il_text, f"Expected conditional on z flag, got: {il_text}"
    assert il_text.count('jump(lr)') == 2, f"Expected 2 returns, got: {il_text}"

    # LLIL should be stable across reanalysis
    assert all_il_before == all_il_after, "LLIL changed after reanalysis"


@pytest.mark.requires_binaryninja
def test_conditional_pc_write_sequence(binaryninja_module):
    """Test conditional PC write (MOV PC, LR) - tests SetRegisterOrBranch with PC.

    Code: CMP r0,#0; MOVEQ pc,lr; ADD r0,r0,#1; BX lr
    This is a data-processing instruction writing PC conditionally.

    This hits ConditionExecuteSetRegisterOrBranch() and if PC writes
    aren't treated as terminators, BN will crash during reanalysis.
    """
    # CMP r0,#0; MOVEQ pc,lr; ADD r0,r0,#1; BX lr
    code = bytes.fromhex('000050e3' '0ef0a001' '010080e2' '1eff2fe1')

    arch = binaryninja_module.Architecture['armv5']
    bv = binaryninja_module.binaryview.BinaryView.new(code)
    bv.add_function(0, plat=arch.standalone_platform)

    assert len(bv.functions) == 1, "Function should be created"
    func = bv.functions[0]

    # First analysis pass
    bv.update_analysis_and_wait()

    # Collect LLIL before reanalysis
    all_il_before = []
    for block in func.low_level_il:
        for il in block:
            all_il_before.append(str(il))

    # Force reanalysis - this is where malformed LLIL crashes
    func.reanalyze()
    bv.update_analysis_and_wait()

    # Collect LLIL after reanalysis
    all_il_after = []
    for block in func.low_level_il:
        for il in block:
            all_il_after.append(str(il))

    # Verify we have the expected structure:
    # - A conditional (if flag:z)
    # - Two paths that end execution (jump to lr)
    il_text = '; '.join(all_il_after)
    assert 'if (flag:z)' in il_text, f"Expected conditional on z flag, got: {il_text}"

    # LLIL should be stable across reanalysis
    assert all_il_before == all_il_after, "LLIL changed after reanalysis"


@pytest.mark.parametrize("data,expected", LLIL_LIKELY_DATA_TESTS)
@pytest.mark.requires_binaryninja
def test_llil_likely_data(data, expected, binaryninja_module):
    """Test that likely data patterns are rejected."""
    actual = instr_to_il(data, 'armv5', binaryninja_module, expect_rejected=True)
    assert actual == expected, f"IsLikelyData mismatch for {data.hex()}: expected rejection, got '{actual}'"
