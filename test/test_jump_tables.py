"""Tests for ARM jump table (switch statement) detection and handling.

ARM switch tables use the pattern:
    ADD PC, PC, Rn [, shift]
followed by a table of PC-relative offsets.

These tests verify that:
1. Jump tables are detected and typed as uint32_t arrays
2. Each table entry has a comment showing the resolved target address
3. Case targets are properly identified as basic blocks
4. Data references are created from table entries to targets
"""
from __future__ import annotations

from pathlib import Path

import pytest

try:
    import binaryninja as bn
except ImportError:
    bn = None

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="module")
def btrom_view():
    """Load btrom.bin for jump table tests."""
    if bn is None:
        pytest.skip("Binary Ninja Python API not available")

    binary_path = DATA_DIR / "btrom.bin"
    if not binary_path.exists():
        pytest.skip(f"Missing test binary: {binary_path}")

    if "ARMv5 Firmware" not in bn.BinaryViewType:
        pytest.skip("ARMv5 Firmware view type not available")

    view_type = bn.BinaryViewType["ARMv5 Firmware"]
    file_metadata = bn.FileMetadata(str(binary_path))
    view = view_type.open(str(binary_path), file_metadata=file_metadata)
    if view is None:
        pytest.skip(f"Failed to open {binary_path}")

    view.update_analysis_and_wait()
    yield view
    view.file.close()


class TestJumpTableDetection:
    """Tests for jump table detection in btrom.bin."""

    def test_jump_table_at_0x47c_exists(self, btrom_view):
        """Verify the jump table at 0x47c is detected as a data variable."""
        table_addr = 0x47c
        data_var = btrom_view.get_data_var_at(table_addr)

        assert data_var is not None, f"Expected data variable at 0x{table_addr:x}"
        assert "uint32_t" in str(data_var.type), f"Expected uint32_t array, got {data_var.type}"
        assert "[" in str(data_var.type), f"Expected array type, got {data_var.type}"

    def test_jump_table_at_0x47c_has_10_entries(self, btrom_view):
        """Verify the jump table at 0x47c has exactly 10 entries."""
        table_addr = 0x47c
        data_var = btrom_view.get_data_var_at(table_addr)

        assert data_var is not None
        # Type should be uint32_t[0xa] or uint32_t[10]
        type_str = str(data_var.type)
        assert "0xa" in type_str or "[10]" in type_str, f"Expected 10 entries, got {type_str}"

    def test_jump_table_at_0x47c_has_comments(self, btrom_view):
        """Verify each jump table entry has a comment with the target address."""
        table_addr = 0x47c
        expected_targets = [0x4a8, 0x4b8, 0x4c4, 0x4d8, 0x4ec, 0x580, 0x5ec, 0x61c, 0x698, 0x754]

        for i, expected_target in enumerate(expected_targets):
            entry_addr = table_addr + (i * 4)
            comment = btrom_view.get_comment_at(entry_addr)

            assert comment is not None, f"Expected comment at entry {i} (0x{entry_addr:x})"
            assert f"0x{expected_target:x}" in comment.lower(), (
                f"Expected target 0x{expected_target:x} in comment at entry {i}, got: {comment}"
            )

    def test_jump_table_at_0x47c_has_data_refs(self, btrom_view):
        """Verify data references exist from table entries to targets."""
        table_addr = 0x47c
        expected_targets = [0x4a8, 0x4b8, 0x4c4, 0x4d8, 0x4ec, 0x580, 0x5ec, 0x61c, 0x698, 0x754]

        for i, expected_target in enumerate(expected_targets):
            entry_addr = table_addr + (i * 4)
            refs = list(btrom_view.get_data_refs_from(entry_addr))

            assert expected_target in refs, (
                f"Expected data ref to 0x{expected_target:x} from entry {i} (0x{entry_addr:x}), "
                f"got refs to {[hex(r) for r in refs]}"
            )

    def test_jump_table_targets_are_basic_blocks(self, btrom_view):
        """Verify all jump table targets become basic block starts."""
        func = btrom_view.get_function_at(0x39c)
        assert func is not None, "Expected function at 0x39c"

        block_starts = {block.start for block in func.basic_blocks}
        expected_targets = [0x4a8, 0x4b8, 0x4c4, 0x4d8, 0x4ec, 0x580, 0x5ec, 0x61c, 0x698, 0x754]

        for target in expected_targets:
            assert target in block_starts, (
                f"Expected basic block at switch target 0x{target:x}"
            )

    def test_jump_table_at_0x640_exists(self, btrom_view):
        """Verify the second jump table at 0x640 is also detected."""
        table_addr = 0x640
        data_var = btrom_view.get_data_var_at(table_addr)

        assert data_var is not None, f"Expected data variable at 0x{table_addr:x}"
        assert "uint32_t" in str(data_var.type), f"Expected uint32_t array, got {data_var.type}"

    def test_jump_table_at_0x640_has_5_entries(self, btrom_view):
        """Verify the jump table at 0x640 has exactly 5 entries."""
        table_addr = 0x640
        data_var = btrom_view.get_data_var_at(table_addr)

        assert data_var is not None
        type_str = str(data_var.type)
        assert "0x5" in type_str or "[5]" in type_str, f"Expected 5 entries, got {type_str}"

    def test_no_duplicate_basic_blocks(self, btrom_view):
        """Verify switch targets don't create duplicate basic blocks."""
        func = btrom_view.get_function_at(0x39c)
        assert func is not None

        # Count blocks at each address
        block_addrs = [block.start for block in func.basic_blocks]
        addr_counts = {}
        for addr in block_addrs:
            addr_counts[addr] = addr_counts.get(addr, 0) + 1

        duplicates = {addr: count for addr, count in addr_counts.items() if count > 1}
        assert not duplicates, f"Found duplicate basic blocks: {duplicates}"


class TestJumpTableEncoding:
    """Tests for ARM jump table instruction encoding."""

    def test_add_pc_pc_rn_encoding(self):
        """Verify ADD PC, PC, Rn encoding is 0xE08FF00x."""
        # ADD PC, PC, r7 = 0xE08FF007
        instr = 0xE08FF007
        assert (instr & 0x0FFFF000) == 0x008FF000, "Should match ADD PC, PC, Rn pattern"
        assert (instr & 0xF) == 7, "Should have r7 as Rm"

    def test_add_pc_pc_rn_shifted_encoding(self):
        """Verify ADD PC, PC, Rn, LSL #2 encoding."""
        # ADD PC, PC, r0, LSL #2 = 0xE08FF100
        # Shift amount in bits [11:7], shift type in bits [6:5]
        instr = 0xE08FF100
        assert (instr & 0x0FFFF000) == 0x008FF000, "Should match ADD PC, PC, Rn pattern"
        assert (instr & 0xF) == 0, "Should have r0 as Rm"
        shift_imm = (instr >> 7) & 0x1F
        assert shift_imm == 2, f"Should have LSL #2, got shift #{shift_imm}"

    def test_table_offset_calculation(self):
        """Verify PC-relative offset calculation for jump tables.

        For ADD PC, PC, Rn at address A:
        - PC reads as A + 8 (ARM pipeline)
        - Result = (A + 8) + offset
        - Table starts at A + 4
        """
        jump_addr = 0x478
        pc_value = jump_addr + 8  # ARM pipeline: PC = instruction address + 8

        # Table entry 0 has offset 0x28
        offset = 0x28
        target = pc_value + offset

        assert target == 0x4a8, f"Expected target 0x4a8, got 0x{target:x}"
