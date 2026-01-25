"""
Detection coverage analysis: find gaps in function detection.

Identifies regions of the binary where function density is anomalously low
compared to surrounding areas, suggesting missed functions.

Run with:
    python -m pytest test/test_detection_coverage.py -s -v

Or standalone:
    BN_USER_DIRECTORY=/Users/ck/.binaryninja-dev python test/test_detection_coverage.py /path/to/firmware.bin
"""
from __future__ import annotations

import os
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import binaryninja as bn
    from binaryninja.plugin import BackgroundTask
    from binaryninja.enums import AnalysisState
except ImportError:
    bn = None

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class RegionStats:
    """Statistics for a region of the binary."""
    start: int
    end: int
    function_count: int
    function_density: float  # functions per KB
    prologue_count: int      # PUSH/STMFD patterns found
    bl_target_count: int     # BL targets pointing into this region
    valid_instr_ratio: float # ratio of valid ARM/Thumb instructions

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def size_kb(self) -> float:
        return self.size / 1024


@dataclass
class SparseRegion:
    """A region with anomalously low function density."""
    start: int
    end: int
    function_count: int
    expected_count: int      # based on surrounding density
    density: float
    surrounding_density: float

    # Analysis of what's in the gap
    prologue_addresses: List[int] = field(default_factory=list)
    bl_target_addresses: List[int] = field(default_factory=list)
    potential_functions: List[int] = field(default_factory=list)

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def size_kb(self) -> float:
        return self.size / 1024

    @property
    def missing_estimate(self) -> int:
        return max(0, self.expected_count - self.function_count)


# ---------------------------------------------------------------------------
# ARM instruction analysis helpers
# ---------------------------------------------------------------------------

def is_arm_prologue(word: int) -> bool:
    """Check if 32-bit word is an ARM prologue instruction."""
    cond = (word >> 28) & 0xF
    if cond > 0xE:
        return False

    # PUSH/STMFD sp!, {..., lr}
    if (word & 0x0FFF0000) == 0x092D0000:
        reglist = word & 0xFFFF
        if reglist & (1 << 14):  # LR in reglist
            return True

    # SUB sp, sp, #imm
    if (word & 0x0FFF0000) == 0x024DD000:
        return True

    # MOV r11, sp or MOV ip, sp
    if (word & 0x0FFFFFFF) in (0x01A0B00D, 0x01A0C00D):
        return True

    # STR lr, [sp, #-4]!
    if (word & 0x0FFFFFFF) == 0x052DE004:
        return True

    return False


def is_thumb_prologue(hw1: int, hw2: int) -> bool:
    """Check if Thumb halfwords form a prologue."""
    # PUSH {regs, lr}
    if (hw1 & 0xFE00) == 0xB400 and (hw1 & 0x0100):
        return True

    # SUB sp, #imm
    if (hw1 & 0xFF80) == 0xB080:
        return True

    # 32-bit PUSH.W with LR
    if hw1 == 0xE92D and (hw2 & (1 << 14)):
        return True

    return False


def is_valid_arm_instruction(word: int) -> bool:
    """Check if word could be a valid ARM instruction."""
    if word == 0x00000000 or word == 0xFFFFFFFF:
        return False

    cond = (word >> 28) & 0xF
    if cond > 0xE:
        # 0xF is unconditional space - only some instructions valid
        # For simplicity, accept common ones
        op = (word >> 24) & 0xF
        if op in (0xA, 0xB):  # BLX
            return True
        return False

    return True


def is_arm_bl_instruction(word: int) -> Tuple[bool, Optional[int], bool]:
    """
    Check if word is BL/BLX instruction.
    Returns (is_bl, target_offset, is_blx).
    """
    cond = (word >> 28) & 0xF

    # BL <label>
    if (word & 0x0F000000) == 0x0B000000 and cond <= 0xE:
        offset = word & 0x00FFFFFF
        if offset & 0x00800000:
            offset |= 0xFF000000
        offset = (offset << 2) + 8
        return True, offset, False

    # BLX <label>
    if (word & 0xFE000000) == 0xFA000000:
        offset = word & 0x00FFFFFF
        if offset & 0x00800000:
            offset |= 0xFF000000
        offset = (offset << 2) + ((word >> 23) & 2) + 8
        return True, offset, True

    return False, None, False


# ---------------------------------------------------------------------------
# Coverage analysis
# ---------------------------------------------------------------------------

def analyze_region(view: 'bn.BinaryView', start: int, end: int) -> RegionStats:
    """Analyze a region of the binary for function detection metrics."""
    functions = [f for f in view.functions if start <= f.start < end]
    size_kb = (end - start) / 1024

    # Count prologues
    prologue_count = 0
    valid_instr_count = 0
    total_words = 0

    # Read the region
    data = view.read(start, end - start)
    if len(data) < 4:
        return RegionStats(start, end, len(functions), 0, 0, 0, 0)

    # Scan for ARM prologues and valid instructions
    for offset in range(0, len(data) - 3, 4):
        word = struct.unpack('<I', data[offset:offset+4])[0]
        total_words += 1

        if is_valid_arm_instruction(word):
            valid_instr_count += 1

        if is_arm_prologue(word):
            prologue_count += 1

    # Count BL targets into this region
    bl_target_count = 0
    for addr in range(view.start, view.end - 3, 4):
        if addr >= start and addr < end:
            continue  # Skip BLs within the region itself

        word_data = view.read(addr, 4)
        if len(word_data) < 4:
            continue
        word = struct.unpack('<I', word_data)[0]

        is_bl, offset, _ = is_arm_bl_instruction(word)
        if is_bl and offset:
            target = addr + offset
            if start <= target < end:
                bl_target_count += 1

    valid_ratio = valid_instr_count / total_words if total_words > 0 else 0
    density = len(functions) / size_kb if size_kb > 0 else 0

    return RegionStats(
        start=start,
        end=end,
        function_count=len(functions),
        function_density=density,
        prologue_count=prologue_count,
        bl_target_count=bl_target_count,
        valid_instr_ratio=valid_ratio
    )


def find_sparse_regions(
    view: 'bn.BinaryView',
    window_size: int = 0x10000,  # 64KB windows
    min_density_ratio: float = 0.3,  # Flag if density < 30% of surrounding
    min_gap_size: int = 0x4000,  # Minimum 16KB gap to report
    code_end: Optional[int] = None,  # Optional: ignore regions past this address
) -> List[SparseRegion]:
    """
    Find regions with anomalously low function density.

    Scans the binary in windows, identifies regions where density drops
    significantly compared to surrounding areas.
    """
    # Get all function addresses sorted
    func_addrs = sorted(f.start for f in view.functions)
    if len(func_addrs) < 10:
        return []  # Not enough functions to analyze

    # Calculate density in windows
    start = view.start
    end = code_end if code_end else view.end

    windows = []
    addr = start
    while addr < end:
        window_end = min(addr + window_size, end)
        funcs_in_window = sum(1 for f in func_addrs if addr <= f < window_end)
        size_kb = (window_end - addr) / 1024
        density = funcs_in_window / size_kb if size_kb > 0 else 0
        windows.append((addr, window_end, funcs_in_window, density))
        addr = window_end

    # Find sparse regions
    sparse_regions = []

    for i, (w_start, w_end, w_count, w_density) in enumerate(windows):
        # Calculate surrounding density (2 windows before and after)
        surrounding = []
        for j in range(max(0, i-2), min(len(windows), i+3)):
            if j != i:
                surrounding.append(windows[j][3])

        if not surrounding:
            continue

        avg_surrounding = sum(surrounding) / len(surrounding)

        # Check if this window is sparse compared to surroundings
        if avg_surrounding > 0 and w_density < avg_surrounding * min_density_ratio:
            # This window looks sparse - expand to find full extent
            region_start = w_start
            region_end = w_end

            # Expand backward
            for j in range(i-1, -1, -1):
                if windows[j][3] < avg_surrounding * min_density_ratio:
                    region_start = windows[j][0]
                else:
                    break

            # Expand forward
            for j in range(i+1, len(windows)):
                if windows[j][3] < avg_surrounding * min_density_ratio:
                    region_end = windows[j][1]
                else:
                    break

            # Check if region is large enough
            if region_end - region_start >= min_gap_size:
                funcs_in_region = sum(1 for f in func_addrs if region_start <= f < region_end)
                region_size_kb = (region_end - region_start) / 1024
                region_density = funcs_in_region / region_size_kb if region_size_kb > 0 else 0
                expected = int(avg_surrounding * region_size_kb)

                # Avoid duplicates
                if not any(r.start == region_start for r in sparse_regions):
                    sparse_regions.append(SparseRegion(
                        start=region_start,
                        end=region_end,
                        function_count=funcs_in_region,
                        expected_count=expected,
                        density=region_density,
                        surrounding_density=avg_surrounding
                    ))

    return sparse_regions


def analyze_sparse_region(view: 'bn.BinaryView', region: SparseRegion) -> None:
    """
    Analyze a sparse region to find potential missed functions.
    Updates the region object with findings.
    """
    data = view.read(region.start, region.end - region.start)
    if len(data) < 4:
        return

    # Find prologue patterns
    for offset in range(0, len(data) - 3, 4):
        addr = region.start + offset
        word = struct.unpack('<I', data[offset:offset+4])[0]

        if is_arm_prologue(word):
            # Check if there's already a function here
            existing = view.get_functions_containing(addr)
            if not existing or all(f.start != addr for f in existing):
                region.prologue_addresses.append(addr)

    # Find BL targets into this region from outside
    bl_targets = set()

    # Scan before the region
    scan_start = max(view.start, region.start - 0x100000)  # 1MB before
    for addr in range(scan_start, region.start, 4):
        word_data = view.read(addr, 4)
        if len(word_data) < 4:
            continue
        word = struct.unpack('<I', word_data)[0]

        is_bl, offset, _ = is_arm_bl_instruction(word)
        if is_bl and offset:
            target = addr + offset
            if region.start <= target < region.end:
                bl_targets.add(target)

    # Scan after the region
    scan_end = min(view.end, region.end + 0x100000)  # 1MB after
    for addr in range(region.end, scan_end, 4):
        word_data = view.read(addr, 4)
        if len(word_data) < 4:
            continue
        word = struct.unpack('<I', word_data)[0]

        is_bl, offset, _ = is_arm_bl_instruction(word)
        if is_bl and offset:
            target = addr + offset
            if region.start <= target < region.end:
                bl_targets.add(target)

    region.bl_target_addresses = sorted(bl_targets)

    # Combine: addresses that are both BL targets AND have prologues are very likely functions
    prologue_set = set(region.prologue_addresses)
    region.potential_functions = sorted(
        addr for addr in bl_targets if addr in prologue_set
    )

    # Also add BL targets that aren't existing functions
    existing_funcs = set(f.start for f in view.functions)
    for addr in bl_targets:
        if addr not in existing_funcs and addr not in region.potential_functions:
            region.potential_functions.append(addr)

    region.potential_functions = sorted(set(region.potential_functions))


def print_coverage_report(view: 'bn.BinaryView', sparse_regions: List[SparseRegion]) -> None:
    """Print a coverage analysis report."""
    total_funcs = len(list(view.functions))
    binary_size = view.end - view.start
    overall_density = total_funcs / (binary_size / 1024)

    print(f"\n{'='*70}")
    print(f"FUNCTION DETECTION COVERAGE REPORT")
    print(f"{'='*70}")
    print(f"Binary range: {view.start:#x} - {view.end:#x} ({binary_size / (1024*1024):.1f} MB)")
    print(f"Total functions: {total_funcs}")
    print(f"Overall density: {overall_density:.2f} functions/KB")
    print()

    if not sparse_regions:
        print("No sparse regions detected - coverage looks uniform.")
        return

    print(f"SPARSE REGIONS DETECTED: {len(sparse_regions)}")
    print(f"{'='*70}")

    total_missing = 0
    total_potential = 0

    for i, region in enumerate(sparse_regions, 1):
        print(f"\n[{i}] {region.start:#x} - {region.end:#x} ({region.size_kb:.1f} KB)")
        print(f"    Functions found: {region.function_count}")
        print(f"    Expected (based on surrounding): ~{region.expected_count}")
        print(f"    Density: {region.density:.2f}/KB (surrounding: {region.surrounding_density:.2f}/KB)")
        print(f"    Missing estimate: ~{region.missing_estimate} functions")

        if region.prologue_addresses:
            print(f"    Prologue patterns found: {len(region.prologue_addresses)}")
            for addr in region.prologue_addresses[:5]:
                print(f"        {addr:#x}")
            if len(region.prologue_addresses) > 5:
                print(f"        ... and {len(region.prologue_addresses) - 5} more")

        if region.bl_target_addresses:
            print(f"    BL targets into region: {len(region.bl_target_addresses)}")
            for addr in region.bl_target_addresses[:5]:
                print(f"        {addr:#x}")
            if len(region.bl_target_addresses) > 5:
                print(f"        ... and {len(region.bl_target_addresses) - 5} more")

        if region.potential_functions:
            print(f"    HIGH-CONFIDENCE missed functions: {len(region.potential_functions)}")
            for addr in region.potential_functions[:10]:
                print(f"        {addr:#x}")
            if len(region.potential_functions) > 10:
                print(f"        ... and {len(region.potential_functions) - 10} more")

        total_missing += region.missing_estimate
        total_potential += len(region.potential_functions)

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Total estimated missing functions: ~{total_missing}")
    print(f"High-confidence candidates found: {total_potential}")
    print(f"Coverage gap: {total_missing / total_funcs * 100:.1f}% of detected functions")


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------

def wait_for_analysis(view: 'bn.BinaryView', timeout_seconds: int = 600) -> None:
    """Wait for the ARMv5 firmware scan to complete."""
    import time

    def find_armv5_task():
        for task in BackgroundTask:
            progress = task.progress or ""
            if "ARMv5" in progress and not task.finished:
                return task
        return None

    start_time = time.time()
    poll_interval = 0.5

    while time.time() - start_time < timeout_seconds:
        task = find_armv5_task()
        if task is not None:
            while not task.finished:
                if time.time() - start_time > timeout_seconds:
                    raise TimeoutError(f"ARMv5 scan timed out. Last: {task.progress}")
                time.sleep(poll_interval)
            view.update_analysis_and_wait()
            return

        if view.analysis_state == AnalysisState.IdleState:
            time.sleep(1.0)
            if find_armv5_task() is None:
                return

        time.sleep(poll_interval)

    raise TimeoutError(f"Timed out waiting for analysis after {timeout_seconds}s")


def run_coverage_analysis(
    view: 'bn.BinaryView',
    code_end: Optional[int] = None
) -> List[SparseRegion]:
    """Run full coverage analysis on a view."""
    if code_end:
        print(f"Finding sparse regions (code boundary: {code_end:#x})...")
    else:
        print(f"Finding sparse regions...")
    sparse_regions = find_sparse_regions(view, code_end=code_end)

    print(f"Analyzing {len(sparse_regions)} sparse regions...")
    for region in sparse_regions:
        analyze_sparse_region(view, region)

    print_coverage_report(view, sparse_regions)
    return sparse_regions


def main():
    """CLI entry point."""
    if bn is None:
        print("Binary Ninja Python API not available")
        sys.exit(1)

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <firmware.bin> [code_end_address]")
        print(f"  code_end_address: Optional hex address (e.g., 0x10af7834) to limit analysis")
        print(f"  If <firmware.bndb> exists, it will be loaded instead of re-analyzing.")
        sys.exit(1)

    binary_path = Path(sys.argv[1])
    code_end = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
    if not binary_path.exists():
        print(f"File not found: {binary_path}")
        sys.exit(1)

    # Check for existing bndb
    bndb_path = binary_path.with_suffix('.bndb')

    if bndb_path.exists():
        print(f"Loading cached analysis from {bndb_path}...")
        view = bn.load(str(bndb_path), update_analysis=False)
        if view is None:
            print(f"Failed to load {bndb_path}")
            sys.exit(1)
        func_count = len(list(view.functions))
        print(f"Loaded: {func_count} functions (skipped re-analysis)")
    else:
        print(f"Loading {binary_path}...")

        if "ARMv5 Firmware" not in bn.BinaryViewType:
            print("ARMv5 Firmware view type not available")
            sys.exit(1)

        view_type = bn.BinaryViewType["ARMv5 Firmware"]
        file_metadata = bn.FileMetadata(str(binary_path))
        view = view_type.open(str(binary_path), file_metadata=file_metadata)

        if view is None:
            print(f"Failed to open {binary_path}")
            sys.exit(1)

        print("Running initial analysis...")
        view.update_analysis_and_wait()

        print("Waiting for firmware scan to complete...")
        wait_for_analysis(view)

        func_count = len(list(view.functions))
        print(f"Analysis complete: {func_count} functions")

        # Save bndb for future runs
        print(f"Saving analysis to {bndb_path}...")
        view.file.create_database(str(bndb_path))
        print(f"Saved.")

    run_coverage_analysis(view, code_end=code_end)

    view.file.close()


if __name__ == "__main__":
    main()
