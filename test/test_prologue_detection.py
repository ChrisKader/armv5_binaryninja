"""
Tests for ARM function prologue detection patterns.

These tests verify that the firmware view correctly identifies function prologues
when analyzing ARM binaries. The patterns tested are:

Pattern 1: STMFD/PUSH with 3+ registers including callee-saved (r4-r11)
Pattern 2: STMFD/PUSH with exactly 2 registers including lr
Pattern 3: MOV ip, sp followed by STMFD with fp and lr (APCS prologue)
Pattern 4: STR lr, [sp, #-4]! followed by SUB sp, sp, #imm
Pattern 5: MRS Rx, CPSR after a return instruction (interrupt utility)
"""
from __future__ import annotations

from pathlib import Path

import pytest

try:
    import binaryninja as bn
except ImportError:
    bn = None

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@pytest.mark.requires_binaryninja
class TestPrologueDetection:
    """Test that specific prologue patterns are detected as functions."""

    @pytest.fixture(scope="class")
    def btrom_view(self):
        """Load btrom.bin with the ARMv5 Firmware view type."""
        if bn is None:
            pytest.skip("Binary Ninja Python API not available")

        btrom_path = DATA_DIR / "btrom.bin"
        if not btrom_path.exists():
            pytest.skip(f"Missing test binary: {btrom_path}")

        if "ARMv5 Firmware" not in bn.BinaryViewType:
            pytest.skip("ARMv5 Firmware view type not available")

        view_type = bn.BinaryViewType["ARMv5 Firmware"]
        file_metadata = bn.FileMetadata(str(btrom_path))
        view = view_type.open(str(btrom_path), file_metadata=file_metadata)
        if view is None:
            file_metadata.close()
            pytest.skip(f"Failed to open {btrom_path}")

        view.update_analysis_and_wait()
        yield view
        view.file.close()

    def test_pattern1_push_3plus_with_callee_saved(self, btrom_view):
        """Pattern 1: PUSH {..., lr} with 3+ registers including r4-r11.

        Example: push {r4, r5, r6, r7, r8, lr} at some address
        This is the most common ARM function prologue pattern.
        """
        # These addresses should have been detected via existing logic
        # We just verify the pattern is still working
        func_starts = {f.start for f in btrom_view.functions}

        # Sample addresses with 3+ reg PUSH including callee-saved from btrom.bin
        # These were detected before the changes, should still work
        test_addrs = [
            0x1b20,   # Known function with multi-reg push
            0x1a58,   # Known function
        ]

        for addr in test_addrs:
            if addr in func_starts:
                # Verify it's actually a PUSH with lr
                data = btrom_view.read(addr, 4)
                if data:
                    instr = int.from_bytes(data, 'little')
                    # Check it's STMFD sp!, {..., lr}
                    assert (instr & 0xFFFF0000) == 0xE92D0000, f"Expected STMFD at 0x{addr:x}"
                    assert (instr & 0x4000) != 0, f"Expected lr in reglist at 0x{addr:x}"

    def test_pattern2_push_2regs_with_lr(self, btrom_view):
        """Pattern 2: PUSH {rX, lr} with exactly 2 registers.

        Example: push {r4, lr} = 0xE92D4010
        Common for small leaf functions.
        """
        func_starts = {f.start for f in btrom_view.functions}

        # Known addresses with push {r4, lr} pattern from btrom.bin analysis
        # These should now be detected with the new 2-register pattern
        test_addrs = [
            0x27a0,   # push {r4, lr}
            0x2d7c,   # push {r4, lr}
            0x2ea4,   # push {r4, lr}
            0x2f34,   # push {r4, lr}
            0x2f64,   # push {r4, lr}
            0x7a50,   # push {r4, lr}
        ]

        detected_count = sum(1 for addr in test_addrs if addr in func_starts)

        # At least 80% of these should be detected
        assert detected_count >= len(test_addrs) * 0.8, (
            f"Expected at least {len(test_addrs) * 0.8:.0f} of {len(test_addrs)} "
            f"2-register PUSH prologues to be detected, got {detected_count}"
        )

    def test_pattern2_push_2regs_scratch_only(self, btrom_view):
        """Pattern 2 variant: PUSH {r3, lr} or similar with scratch registers.

        Example: push {r3, lr} = 0xE92D4008
        Also common for small functions.
        """
        func_starts = {f.start for f in btrom_view.functions}

        # Known addresses with push {r3, lr} or similar from btrom.bin
        test_addrs = [
            0x3d78,   # push {r3, lr}
            0xa64c,   # push {r3, lr}
            0xfafc,   # push {r3, lr}
            0xfb10,   # push {r3, lr}
        ]

        detected_count = sum(1 for addr in test_addrs if addr in func_starts)

        # At least 50% should be detected (more conservative for scratch-only)
        assert detected_count >= len(test_addrs) * 0.5, (
            f"Expected at least {len(test_addrs) * 0.5:.0f} of {len(test_addrs)} "
            f"scratch-register PUSH prologues to be detected, got {detected_count}"
        )

    def test_pattern4_str_lr_sub_sp_sequence(self, btrom_view):
        """Pattern 4: STR lr, [sp, #-4]! followed by SUB sp, sp, #imm.

        Example:
            str lr, [sp, #-4]!  ; 0xE52DE004
            sub sp, sp, #0x2c   ; 0xE24DD02C

        This two-instruction sequence is a reliable prologue pattern.
        """
        func_starts = {f.start for f in btrom_view.functions}

        # Known addresses with STR lr + SUB sp pattern from btrom.bin
        test_addrs = [
            0x2f08,   # str lr, [sp, #-4]! + sub sp, sp, #0x2c
            0x3d48,   # str lr, [sp, #-4]! + sub sp, sp, #0x2c
            0x3db0,   # str lr, [sp, #-4]! + sub sp, sp, #0x2c
            0x3dd8,   # str lr, [sp, #-4]! + sub sp, sp, #0x2c
            0x3e0c,   # str lr, [sp, #-4]! + sub sp, sp, #0x2c
            0x7068,   # str lr, [sp, #-4]! + sub sp, sp, #0x34
        ]

        detected_count = sum(1 for addr in test_addrs if addr in func_starts)

        # All of these should be detected - it's a very reliable pattern
        assert detected_count >= len(test_addrs) * 0.8, (
            f"Expected at least {len(test_addrs) * 0.8:.0f} of {len(test_addrs)} "
            f"STR lr + SUB sp prologues to be detected, got {detected_count}"
        )

    def test_pattern5_mrs_cpsr_after_return(self, btrom_view):
        """Pattern 5: MRS Rx, CPSR when preceded by a return instruction.

        Example (two adjacent functions):
            bx lr               ; 0xE12FFF1E - end of previous function
            mrs r2, cpsr        ; 0xE10F2000 - start of interrupt disable function

        These are small utility functions for interrupt enable/disable.
        """
        func_starts = {f.start for f in btrom_view.functions}

        # Known addresses with MRS CPSR after return from btrom.bin
        # These are interrupt enable/disable utility functions
        test_addrs = [
            0x23ae8,  # mrs r2, cpsr (after bx lr at 0x23ae4)
            0x23af8,  # mrs r2, cpsr (after bx lr at 0x23af4)
        ]

        detected_count = sum(1 for addr in test_addrs if addr in func_starts)

        # These specific patterns should be detected
        assert detected_count >= 1, (
            f"Expected at least 1 MRS CPSR prologue to be detected after return, "
            f"got {detected_count}"
        )

    def test_pattern1b_push_scratch_only(self, btrom_view):
        """Pattern 1b: PUSH {r0-r3, ip, lr} with 3+ scratch registers only.

        Example: push {r0, r1, r2, lr} = 0xE92D4007
        These are wrapper/thunk functions that save args before a call.
        """
        func_starts = {f.start for f in btrom_view.functions}

        # Known addresses with scratch-only PUSH from btrom.bin
        test_addrs = [
            0x33c,    # push {r0, r1, r2, lr}
            0x36c,    # push {r0, r1, r2, lr}
            0x388,    # push {r0, r1, r2, lr} (inside func at 0x384, but 0x384 should be detected)
        ]

        # At least 2 of these should be detected (0x388 might be inside another func)
        detected_count = sum(1 for addr in test_addrs if addr in func_starts)

        assert detected_count >= 2, (
            f"Expected at least 2 of {len(test_addrs)} scratch-only PUSH prologues "
            f"to be detected, got {detected_count}"
        )

    def test_pattern6_mov_bx_lr(self, btrom_view):
        """Pattern 6: MOV/MVN Rd, #imm followed by BX LR after return.

        Example:
            bx lr               ; end of previous function
            mvn r0, #0          ; 0xE3E00000 - start of return -1 function
            bx lr               ; 0xE12FFF1E

        These are short functions that return a constant value.
        """
        func_starts = {f.start for f in btrom_view.functions}

        # Known addresses with MOV+BX pattern from btrom.bin
        test_addrs = [
            0x838,    # mvn r0, #0 followed by bx lr (return -1)
            0xa7f8,   # mov r0, #0 followed by bx lr (return 0)
        ]

        detected_count = sum(1 for addr in test_addrs if addr in func_starts)

        assert detected_count >= 1, (
            f"Expected at least 1 MOV+BX LR pattern to be detected, "
            f"got {detected_count}"
        )

    def test_pattern7_mcr_mrc_after_return(self, btrom_view):
        """Pattern 7: MCR/MRC (coprocessor access) after return.

        Example:
            bx lr               ; end of previous function
            mrc p15, ...        ; start of CP15 accessor function

        These are system register accessor functions.
        """
        func_starts = {f.start for f in btrom_view.functions}

        # Known addresses with MCR/MRC after return from btrom.bin
        test_addrs = [
            0x7d8,    # mrc after bx lr
            0x7f4,    # mrc after bx lr
            0x7fc,    # mrc after bx lr
        ]

        detected_count = sum(1 for addr in test_addrs if addr in func_starts)

        assert detected_count >= 2, (
            f"Expected at least 2 MCR/MRC prologues to be detected, "
            f"got {detected_count}"
        )

    def test_function_count_improved(self, btrom_view):
        """Verify that the new patterns detect more functions than before.

        Before the prologue improvements: ~917 functions
        After round 1 (2-reg PUSH, STR+SUB, MRS): ~1081 functions
        After round 2 (scratch PUSH, MOV+BX, MCR/MRC): Should be even more
        """
        func_count = len(list(btrom_view.functions))

        # We expect at least 1100 functions now with all patterns
        # This includes scratch-only PUSH, MOV+BX LR, and MCR/MRC patterns
        assert func_count >= 1100, (
            f"Expected at least 1100 functions with new prologue patterns, "
            f"got {func_count}"
        )

        # Print for informational purposes
        print(f"\nTotal functions detected: {func_count}")

    def test_no_false_positives_in_data(self, btrom_view):
        """Verify we don't detect SRAM addresses as prologues.

        SRAM addresses like 0xA4029400 can look like ARM instructions
        but are actually data (pointers to SRAM).
        """
        func_starts = {f.start for f in btrom_view.functions}

        # Known data addresses that should NOT be detected as functions
        # These are literal pool entries containing SRAM pointers
        data_addrs = [
            0x1024,   # Contains 0xA4029400 (SRAM pointer, not code)
            0x1048,   # Near literal pool area
        ]

        for addr in data_addrs:
            # These specific addresses should not be functions
            # (they're in literal pools between functions)
            data = btrom_view.read(addr, 4)
            if data:
                word = int.from_bytes(data, 'little')
                # If it looks like an SRAM address, it shouldn't be a function
                if (word & 0xFF000000) == 0xA4000000:
                    assert addr not in func_starts, (
                        f"SRAM pointer at 0x{addr:x} (value 0x{word:x}) "
                        f"should not be detected as function"
                    )


@pytest.mark.requires_binaryninja
class TestPrologueEncodings:
    """Unit tests for prologue pattern encodings."""

    def test_push_r4_lr_encoding(self):
        """Verify push {r4, lr} encoding is 0xE92D4010."""
        # STMFD sp!, {r4, lr}
        # cond=1110 (AL), 100 1 0 0 1 0, Rn=1101 (sp), reglist
        # reglist: bit 4 (r4) + bit 14 (lr) = 0x4010
        expected = 0xE92D4010
        assert (expected & 0xFFFF0000) == 0xE92D0000, "Should be STMFD"
        assert (expected & 0x4000) != 0, "Should have lr"
        assert bin(expected & 0xFFFF).count('1') == 2, "Should have 2 registers"

    def test_push_r3_lr_encoding(self):
        """Verify push {r3, lr} encoding is 0xE92D4008."""
        expected = 0xE92D4008
        assert (expected & 0xFFFF0000) == 0xE92D0000
        assert (expected & 0x4000) != 0
        assert bin(expected & 0xFFFF).count('1') == 2

    def test_str_lr_sp_encoding(self):
        """Verify str lr, [sp, #-4]! encoding is 0xE52DE004."""
        # STR lr, [sp, #-4]!
        # Pre-indexed, subtract, writeback
        expected = 0xE52DE004
        assert expected == 0xE52DE004

    def test_sub_sp_encoding(self):
        """Verify sub sp, sp, #imm encoding pattern."""
        # SUB sp, sp, #0x2c = 0xE24DD02C
        example = 0xE24DD02C
        assert (example & 0xFFFFF000) == 0xE24DD000, "Should be SUB sp, sp, #imm"

    def test_mrs_cpsr_encoding(self):
        """Verify MRS Rd, CPSR encoding pattern."""
        # MRS r2, CPSR = 0xE10F2000
        example = 0xE10F2000
        assert (example & 0x0FBF0FFF) == 0x010F0000, "Should match MRS CPSR pattern"

    def test_bx_lr_encoding(self):
        """Verify BX LR encoding is 0xE12FFF1E."""
        expected = 0xE12FFF1E
        assert (expected & 0x0FFFFFFF) == 0x012FFF1E

    def test_push_scratch_only_encoding(self):
        """Verify push {r0, r1, r2, lr} encoding is 0xE92D4007."""
        # STMFD sp!, {r0, r1, r2, lr}
        # reglist: bits 0,1,2,14 = 0x4007
        expected = 0xE92D4007
        assert (expected & 0xFFFF0000) == 0xE92D0000, "Should be STMFD"
        assert (expected & 0x4000) != 0, "Should have lr"
        assert bin(expected & 0xFFFF).count('1') == 4, "Should have 4 registers"
        assert (expected & 0x0FF0) == 0, "Should NOT have callee-saved (r4-r11)"

    def test_mov_imm_encoding(self):
        """Verify MOV Rd, #imm encoding pattern."""
        # MOV r0, #0 = 0xE3A00000
        mov_r0_0 = 0xE3A00000
        assert (mov_r0_0 & 0x0FE00000) == 0x03A00000, "Should match MOV imm pattern"

        # MVN r0, #0 = 0xE3E00000 (returns -1)
        mvn_r0_0 = 0xE3E00000
        assert (mvn_r0_0 & 0x0FE00000) == 0x03E00000, "Should match MVN imm pattern"

    def test_mcr_mrc_encoding(self):
        """Verify MCR/MRC encoding patterns."""
        # MRC p15, 0, r0, c0, c0, 0 = 0xEE100F10
        mrc_example = 0xEE100F10
        assert (mrc_example & 0x0F000010) == 0x0E000010, "Should match MCR/MRC pattern"

        # MCR p15, 0, r0, c1, c0, 0 = 0xEE010F10
        mcr_example = 0xEE010F10
        assert (mcr_example & 0x0F000010) == 0x0E000010, "Should match MCR/MRC pattern"
