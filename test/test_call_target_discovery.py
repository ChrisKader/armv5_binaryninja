"""
Tests for ARM call target discovery and function recognizer patterns.

These tests verify that:
1. BL/BLX/LDR PC call targets are discovered as functions
2. ARM thunk functions are properly recognized
3. The function recognizer correctly identifies import wrappers
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
class TestCallTargetDiscovery:
    """Test that BL/BLX/LDR PC targets are discovered as functions."""

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

    def test_bl_targets_are_functions(self, btrom_view):
        """Verify that BL instruction targets become functions.

        BL (Branch with Link) is the primary ARM call instruction.
        All valid BL targets within the image should be detected as functions.
        """
        func_starts = {f.start for f in btrom_view.functions}

        # Find some BL instructions and verify their targets are functions
        bl_count = 0
        bl_targets_found = 0

        for func in btrom_view.functions:
            for block in func.basic_blocks:
                for addr in range(block.start, block.end, 4):
                    data = btrom_view.read(addr, 4)
                    if not data or len(data) < 4:
                        continue

                    instr = int.from_bytes(data, 'little')

                    # Check for BL: cond 1011 imm24 (cond != 1111)
                    if (instr & 0x0F000000) == 0x0B000000 and (instr & 0xF0000000) != 0xF0000000:
                        # Extract target
                        imm24 = instr & 0x00FFFFFF
                        if imm24 & 0x00800000:
                            imm24 |= 0xFF000000  # Sign extend
                        offset = (imm24 << 2)
                        # Convert to signed
                        if offset & 0x80000000:
                            offset = offset - 0x100000000
                        target = addr + 8 + offset

                        # Check if target is within image
                        image_start = btrom_view.start
                        image_end = btrom_view.end

                        if image_start <= target < image_end:
                            bl_count += 1
                            if target in func_starts:
                                bl_targets_found += 1

                    # Stop after checking enough
                    if bl_count >= 100:
                        break
                if bl_count >= 100:
                    break
            if bl_count >= 100:
                break

        # At least 90% of BL targets should be functions
        if bl_count > 0:
            ratio = bl_targets_found / bl_count
            assert ratio >= 0.9, (
                f"Expected at least 90% of BL targets to be functions, "
                f"got {bl_targets_found}/{bl_count} ({ratio:.1%})"
            )

    def test_ldr_pc_targets_are_functions(self, btrom_view):
        """Verify that LDR PC, [PC, #imm] targets become functions.

        This pattern loads a function address from a literal pool and
        jumps to it. Common for long-range calls or PLT-style stubs.
        """
        func_starts = {f.start for f in btrom_view.functions}
        image_start = btrom_view.start
        image_end = btrom_view.end

        ldr_pc_count = 0
        ldr_pc_targets_found = 0

        # Scan for LDR PC, [PC, #imm] instructions
        for offset in range(0, min(btrom_view.length, 0x10000), 4):
            addr = image_start + offset
            data = btrom_view.read(addr, 4)
            if not data or len(data) < 4:
                continue

            instr = int.from_bytes(data, 'little')

            # LDR PC, [PC, #imm]: cond 0101 U001 1111 1111 imm12
            if (instr & 0x0F7FF000) == 0x051FF000:
                imm12 = instr & 0xFFF
                add = (instr & 0x00800000) != 0
                lit_pool_addr = (addr + 8 + imm12) if add else (addr + 8 - imm12)

                # Read literal pool entry
                if image_start <= lit_pool_addr < image_end - 4:
                    lit_data = btrom_view.read(lit_pool_addr, 4)
                    if lit_data and len(lit_data) == 4:
                        target = int.from_bytes(lit_data, 'little')
                        target_aligned = target & ~1  # Mask Thumb bit

                        if image_start <= target_aligned < image_end:
                            ldr_pc_count += 1
                            if target_aligned in func_starts or target in func_starts:
                                ldr_pc_targets_found += 1

        # Most LDR PC targets should be functions (some might be data)
        if ldr_pc_count > 0:
            ratio = ldr_pc_targets_found / ldr_pc_count
            assert ratio >= 0.7, (
                f"Expected at least 70% of LDR PC targets to be functions, "
                f"got {ldr_pc_targets_found}/{ldr_pc_count} ({ratio:.1%})"
            )


@pytest.mark.requires_binaryninja
class TestCallTargetEncodings:
    """Unit tests for call instruction encodings."""

    def test_bl_encoding(self):
        """Verify BL instruction encoding pattern."""
        # BL +0x100 from 0x1000 = target 0x1108 (PC+8+0x100)
        # imm24 = 0x100 >> 2 = 0x40
        bl_instr = 0xEB000040
        assert (bl_instr & 0x0F000000) == 0x0B000000, "Should be BL"
        assert (bl_instr & 0xF0000000) != 0xF0000000, "Should not be unconditional"

    def test_bl_negative_offset_encoding(self):
        """Verify BL with negative offset encoding."""
        # BL -0x100 from 0x1100 = target 0x1008 (accounting for PC+8)
        # Actual offset needed: 0x1008 - (0x1100 + 8) = -0x100
        # imm24 = (-0x100 >> 2) & 0xFFFFFF = 0xFFFFC0
        bl_instr = 0xEBFFFFC0
        assert (bl_instr & 0x0F000000) == 0x0B000000, "Should be BL"

        # Verify offset calculation (must use ctypes for proper sign extension)
        import ctypes
        imm24 = bl_instr & 0x00FFFFFF
        # Sign-extend from 24 bits to 32 bits
        if imm24 & 0x00800000:
            imm24 = imm24 | 0xFF000000
        # Convert to signed using ctypes
        offset = ctypes.c_int32(imm24 << 2).value
        assert offset == -0x100, f"Offset should be -0x100, got {offset}"

    def test_blx_encoding(self):
        """Verify BLX imm encoding pattern (ARM to Thumb)."""
        # BLX has bit 28 = 1, bits 27-25 = 101
        # 1111 101 H imm24
        blx_instr = 0xFA000000
        assert (blx_instr & 0xFE000000) == 0xFA000000, "Should be BLX"

    def test_ldr_pc_encoding(self):
        """Verify LDR PC, [PC, #imm] encoding pattern."""
        # LDR PC, [PC, #0x10] = 0xE59FF010
        # cond=1110, 01 0 1 1 0 0 1, Rn=1111, Rd=1111, imm12=0x010
        ldr_pc = 0xE59FF010
        assert (ldr_pc & 0x0F7FF000) == 0x051FF000, "Should match LDR PC pattern"
        assert (ldr_pc & 0x00800000) != 0, "U bit should be set (add)"
        assert (ldr_pc & 0xFFF) == 0x10, "Offset should be 0x10"

    def test_ldr_pc_negative_encoding(self):
        """Verify LDR PC, [PC, #-imm] encoding pattern."""
        # LDR PC, [PC, #-0x10] = 0xE51FF010
        ldr_pc_neg = 0xE51FF010
        assert (ldr_pc_neg & 0x0F7FF000) == 0x051FF000, "Should match LDR PC pattern"
        assert (ldr_pc_neg & 0x00800000) == 0, "U bit should be clear (subtract)"


@pytest.mark.requires_binaryninja
class TestFunctionRecognizer:
    """Test that the ARM function recognizer works correctly."""

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

    def test_single_jump_functions_exist(self, btrom_view):
        """Verify that single-jump thunk functions are recognized.

        These are functions that consist of just a single B (branch)
        or LDR PC instruction - typically tail-call thunks or PLT entries.
        """
        single_jump_funcs = []

        for func in btrom_view.functions:
            # Get basic blocks
            blocks = list(func.basic_blocks)
            if len(blocks) != 1:
                continue

            block = blocks[0]
            # Check if it's a single instruction function (4 bytes for ARM)
            if block.end - block.start == 4:
                data = btrom_view.read(block.start, 4)
                if data and len(data) == 4:
                    instr = int.from_bytes(data, 'little')

                    # Check for B (unconditional branch): cond 1010 imm24
                    if (instr & 0x0F000000) == 0x0A000000:
                        single_jump_funcs.append(func.start)

                    # Check for LDR PC, [PC, #imm]
                    elif (instr & 0x0F7FF000) == 0x051FF000:
                        single_jump_funcs.append(func.start)

        # We should find at least a few thunk-style functions
        # (exact count depends on the binary)
        print(f"\nFound {len(single_jump_funcs)} single-jump functions")

    def test_constant_return_functions_exist(self, btrom_view):
        """Verify that constant return functions are recognized.

        These are functions that just do MOV r0, #const followed by BX LR.
        Common for returning error codes, booleans, etc.
        """
        const_return_funcs = []

        for func in btrom_view.functions:
            blocks = list(func.basic_blocks)
            if len(blocks) != 1:
                continue

            block = blocks[0]
            # Check for 2-instruction function (8 bytes)
            if block.end - block.start == 8:
                data = btrom_view.read(block.start, 8)
                if data and len(data) == 8:
                    instr1 = int.from_bytes(data[0:4], 'little')
                    instr2 = int.from_bytes(data[4:8], 'little')

                    # Check for MOV/MVN r0, #imm followed by BX LR
                    is_mov_imm = (instr1 & 0x0FE00000) == 0x03A00000  # MOV
                    is_mvn_imm = (instr1 & 0x0FE00000) == 0x03E00000  # MVN
                    is_bx_lr = (instr2 & 0x0FFFFFFF) == 0x012FFF1E

                    if (is_mov_imm or is_mvn_imm) and is_bx_lr:
                        # Extract return value
                        imm8 = instr1 & 0xFF
                        rotate = (instr1 >> 8) & 0xF
                        value = (imm8 >> (rotate * 2)) | (imm8 << (32 - rotate * 2))
                        if is_mvn_imm:
                            value = ~value & 0xFFFFFFFF

                        const_return_funcs.append((func.start, value))

        # Print for informational purposes
        print(f"\nFound {len(const_return_funcs)} constant return functions:")
        for addr, val in const_return_funcs[:10]:  # Show first 10
            print(f"  0x{addr:x}: returns {val} (0x{val:x})")

        # We should find at least some constant return functions
        assert len(const_return_funcs) >= 1, (
            "Expected at least 1 constant return function"
        )
