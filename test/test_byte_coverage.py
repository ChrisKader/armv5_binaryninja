"""
Byte-level coverage analysis: sweep the binary and categorize every byte.

For each byte position:
- If in a function: assess function quality and bounds
- If in a data var: note it
- If uncovered: track the gap and analyze why

Run with:
    BN_USER_DIRECTORY=/Users/ck/.binaryninja-dev python test/test_byte_coverage.py <binary> [code_end]

Example:
    python test/test_byte_coverage.py data/nspire/.../nspire.bin 0x10af7834
"""
from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple

try:
    import binaryninja as bn
    from binaryninja.plugin import BackgroundTask
    from binaryninja.enums import AnalysisState
except ImportError:
    bn = None


class CoverageType(Enum):
    FUNCTION = auto()
    DATA_VAR = auto()
    UNCOVERED = auto()


@dataclass
class FunctionQuality:
    """Quality assessment of a detected function."""
    address: int
    end: int
    size: int

    # Positive indicators
    has_prologue: bool = False
    has_epilogue: bool = False
    has_callers: bool = False
    caller_count: int = 0
    has_callees: bool = False
    block_count: int = 0

    # Suspicious indicators
    too_small: bool = False          # < 4 bytes
    too_large: bool = False          # > 1MB (likely wrong bounds)
    starts_with_epilogue: bool = False
    no_return_paths: bool = False
    overlaps_data: bool = False

    @property
    def quality_score(self) -> int:
        """0-100 quality score."""
        score = 50  # baseline

        if self.has_prologue: score += 20
        if self.has_epilogue: score += 10
        if self.has_callers: score += 15
        if self.caller_count >= 3: score += 5
        if self.block_count >= 2: score += 5

        if self.too_small: score -= 30
        if self.too_large: score -= 20
        if self.starts_with_epilogue: score -= 40
        if self.overlaps_data: score -= 25

        return max(0, min(100, score))

    @property
    def quality_label(self) -> str:
        s = self.quality_score
        if s >= 80: return "GOOD"
        if s >= 60: return "OK"
        if s >= 40: return "WEAK"
        return "POOR"


@dataclass
class UncoveredGap:
    """A region of bytes not covered by any function or data var."""
    start: int
    end: int

    # Analysis results
    prologue_addresses: List[int] = field(default_factory=list)
    bl_target_addresses: List[int] = field(default_factory=list)
    valid_instruction_ratio: float = 0.0
    looks_like_code: bool = False
    looks_like_data: bool = False

    # Diagnosis
    diagnosis: str = ""

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class CoverageRegion:
    """A contiguous region with the same coverage type."""
    start: int
    end: int
    coverage_type: CoverageType

    # For functions
    function_quality: Optional[FunctionQuality] = None

    # For uncovered gaps
    gap_analysis: Optional[UncoveredGap] = None

    @property
    def size(self) -> int:
        return self.end - self.start


# ---------------------------------------------------------------------------
# ARM instruction helpers
# ---------------------------------------------------------------------------

def is_arm_prologue(word: int) -> bool:
    """Check if 32-bit word is an ARM prologue instruction."""
    cond = (word >> 28) & 0xF
    if cond > 0xE:
        return False

    # PUSH/STMFD sp!, {..., lr}
    if (word & 0x0FFF0000) == 0x092D0000:
        reglist = word & 0xFFFF
        if reglist & (1 << 14):
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


def is_arm_epilogue(word: int) -> bool:
    """Check if 32-bit word is an ARM epilogue/return instruction."""
    cond = (word >> 28) & 0xF

    # BX LR
    if (word & 0x0FFFFFFF) == 0x012FFF1E:
        return True
    # MOV pc, lr
    if (word & 0x0FFFFFFF) == 0x01A0F00E:
        return True
    # POP {..., pc} / LDMIA sp!, {..., pc}
    if (word & 0x0FFF0000) == 0x08BD0000 and (word & (1 << 15)):
        return True
    # LDR pc, [sp], #imm
    if (word & 0x0FFF0000) == 0x049D0000 and ((word >> 12) & 0xF) == 0xF:
        return True

    return False


def is_valid_arm_instruction(word: int) -> bool:
    """Check if word could be a valid ARM instruction."""
    if word == 0x00000000 or word == 0xFFFFFFFF:
        return False

    cond = (word >> 28) & 0xF
    if cond > 0xE:
        # Unconditional space - limited valid instructions
        op = (word >> 24) & 0xF
        return op in (0xA, 0xB)  # BLX

    return True


def extract_bl_target(word: int, addr: int) -> Optional[int]:
    """Extract BL/BLX target address if this is a call instruction."""
    cond = (word >> 28) & 0xF

    # BL <label>
    if (word & 0x0F000000) == 0x0B000000 and cond <= 0xE:
        offset = word & 0x00FFFFFF
        if offset & 0x00800000:
            offset |= 0xFF000000
        offset = (offset << 2) + 8
        return (addr + offset) & 0xFFFFFFFF

    # BLX <label>
    if (word & 0xFE000000) == 0xFA000000:
        offset = word & 0x00FFFFFF
        if offset & 0x00800000:
            offset |= 0xFF000000
        offset = (offset << 2) + ((word >> 23) & 2) + 8
        return (addr + offset) & 0xFFFFFFFF

    return None


# ---------------------------------------------------------------------------
# Coverage analysis
# ---------------------------------------------------------------------------

def build_function_map(view: 'bn.BinaryView') -> Dict[int, 'bn.Function']:
    """Build a map of address -> function for quick lookup."""
    func_map = {}
    for func in view.functions:
        for block in func.basic_blocks:
            for addr in range(block.start, block.end):
                func_map[addr] = func
    return func_map


def build_data_var_set(view: 'bn.BinaryView') -> Set[int]:
    """Build set of addresses covered by data variables."""
    data_addrs = set()
    for addr, dv in view.data_vars.items():
        for i in range(dv.type.width if dv.type else 1):
            data_addrs.add(addr + i)
    return data_addrs


def assess_function_quality(
    view: 'bn.BinaryView',
    func: 'bn.Function',
    data_var_addrs: Set[int],
    bl_targets: Set[int]
) -> FunctionQuality:
    """Assess the quality of a function's detection and bounds."""
    start = func.start

    # Calculate end from basic blocks
    end = start
    for block in func.basic_blocks:
        if block.end > end:
            end = block.end

    size = end - start

    quality = FunctionQuality(
        address=start,
        end=end,
        size=size,
        block_count=len(list(func.basic_blocks))
    )

    # Check prologue
    data = view.read(start, 4)
    if len(data) >= 4:
        word = struct.unpack('<I', data)[0]
        quality.has_prologue = is_arm_prologue(word)
        quality.starts_with_epilogue = is_arm_epilogue(word)

    # Check for epilogue in last block
    blocks = list(func.basic_blocks)
    if blocks:
        last_block = max(blocks, key=lambda b: b.end)
        if last_block.end > last_block.start + 4:
            data = view.read(last_block.end - 4, 4)
            if len(data) >= 4:
                word = struct.unpack('<I', data)[0]
                quality.has_epilogue = is_arm_epilogue(word)

    # Check callers
    callers = list(view.get_code_refs(start))
    quality.caller_count = len(callers)
    quality.has_callers = quality.caller_count > 0

    # Check if it's a BL target
    if start in bl_targets:
        quality.has_callers = True

    # Check callees
    for block in func.basic_blocks:
        for addr in range(block.start, block.end, 4):
            data = view.read(addr, 4)
            if len(data) >= 4:
                word = struct.unpack('<I', data)[0]
                if extract_bl_target(word, addr):
                    quality.has_callees = True
                    break
        if quality.has_callees:
            break

    # Suspicious checks
    quality.too_small = size < 4
    quality.too_large = size > 0x100000  # 1MB

    # Check if function overlaps data vars
    for addr in range(start, min(end, start + 100)):  # Check first 100 bytes
        if addr in data_var_addrs:
            quality.overlaps_data = True
            break

    return quality


def analyze_uncovered_gap(
    view: 'bn.BinaryView',
    gap: UncoveredGap,
    bl_targets: Set[int]
) -> None:
    """Analyze an uncovered gap to determine what it contains."""
    data = view.read(gap.start, gap.size)
    if len(data) < 4:
        gap.diagnosis = "Too small to analyze"
        return

    # Scan for prologues
    for offset in range(0, len(data) - 3, 4):
        word = struct.unpack('<I', data[offset:offset+4])[0]
        if is_arm_prologue(word):
            gap.prologue_addresses.append(gap.start + offset)

    # Check for BL targets into this gap
    for target in bl_targets:
        if gap.start <= target < gap.end:
            gap.bl_target_addresses.append(target)

    # Count valid instructions
    valid_count = 0
    total_count = 0
    zero_count = 0
    ff_count = 0

    for offset in range(0, len(data) - 3, 4):
        word = struct.unpack('<I', data[offset:offset+4])[0]
        total_count += 1

        if word == 0x00000000:
            zero_count += 1
        elif word == 0xFFFFFFFF:
            ff_count += 1
        elif is_valid_arm_instruction(word):
            valid_count += 1

    if total_count > 0:
        gap.valid_instruction_ratio = valid_count / total_count
        padding_ratio = (zero_count + ff_count) / total_count

        gap.looks_like_code = gap.valid_instruction_ratio > 0.7 and padding_ratio < 0.3
        gap.looks_like_data = gap.valid_instruction_ratio < 0.3 or padding_ratio > 0.5

    # Diagnosis
    diagnoses = []

    if gap.prologue_addresses:
        diagnoses.append(f"{len(gap.prologue_addresses)} prologues found but no functions created")

    if gap.bl_target_addresses:
        diagnoses.append(f"{len(gap.bl_target_addresses)} BL targets point here")

    if gap.looks_like_code:
        diagnoses.append("Looks like valid ARM code")
    elif gap.looks_like_data:
        diagnoses.append("Looks like data/padding")
    else:
        diagnoses.append("Mixed code/data")

    gap.diagnosis = "; ".join(diagnoses) if diagnoses else "Unknown"


def sweep_binary(
    view: 'bn.BinaryView',
    start: int,
    end: int,
    verbose: bool = False
) -> List[CoverageRegion]:
    """
    Sweep the binary byte-by-byte and categorize each region.

    Returns list of contiguous regions with their coverage type and analysis.
    """
    print(f"Building coverage maps...")

    # Build lookup structures
    func_map = build_function_map(view)
    data_var_addrs = build_data_var_set(view)

    # Build set of all BL targets for quick lookup
    print(f"Scanning for BL targets...")
    bl_targets: Set[int] = set()
    for addr in range(start, end - 3, 4):
        data = view.read(addr, 4)
        if len(data) >= 4:
            word = struct.unpack('<I', data)[0]
            target = extract_bl_target(word, addr)
            if target and start <= target < end:
                bl_targets.add(target)

    print(f"Found {len(bl_targets)} BL targets")
    print(f"Sweeping {(end - start) / (1024*1024):.1f} MB...")

    regions: List[CoverageRegion] = []
    current_type: Optional[CoverageType] = None
    current_start = start
    current_func: Optional['bn.Function'] = None
    processed_funcs: Set[int] = set()

    addr = start
    last_percent = -1

    while addr < end:
        # Progress
        percent = int((addr - start) * 100 / (end - start))
        if percent != last_percent and percent % 10 == 0:
            print(f"  {percent}% ({addr:#x})")
            last_percent = percent

        # Determine coverage type at this address
        if addr in func_map:
            cov_type = CoverageType.FUNCTION
            func = func_map[addr]
        elif addr in data_var_addrs:
            cov_type = CoverageType.DATA_VAR
            func = None
        else:
            cov_type = CoverageType.UNCOVERED
            func = None

        # Check if we're continuing the same region
        if cov_type == current_type:
            if cov_type == CoverageType.FUNCTION:
                # Same function?
                if func and current_func and func.start == current_func.start:
                    addr += 1
                    continue
            elif cov_type == CoverageType.UNCOVERED:
                # Continue uncovered region
                addr += 1
                continue
            elif cov_type == CoverageType.DATA_VAR:
                # Continue data region
                addr += 1
                continue

        # Type changed or function changed - close current region
        if current_type is not None and addr > current_start:
            region = CoverageRegion(
                start=current_start,
                end=addr,
                coverage_type=current_type
            )

            if current_type == CoverageType.FUNCTION and current_func:
                if current_func.start not in processed_funcs:
                    region.function_quality = assess_function_quality(
                        view, current_func, data_var_addrs, bl_targets
                    )
                    processed_funcs.add(current_func.start)
            elif current_type == CoverageType.UNCOVERED:
                gap = UncoveredGap(start=current_start, end=addr)
                analyze_uncovered_gap(view, gap, bl_targets)
                region.gap_analysis = gap

            regions.append(region)

        # Start new region
        current_type = cov_type
        current_start = addr
        current_func = func

        # Skip to end of current function if we just entered one
        if cov_type == CoverageType.FUNCTION and func:
            # Find the function's end
            func_end = func.start
            for block in func.basic_blocks:
                if block.end > func_end:
                    func_end = block.end
            addr = func_end
        else:
            addr += 1

    # Close final region
    if current_type is not None and addr > current_start:
        region = CoverageRegion(
            start=current_start,
            end=addr,
            coverage_type=current_type
        )
        if current_type == CoverageType.UNCOVERED:
            gap = UncoveredGap(start=current_start, end=addr)
            analyze_uncovered_gap(view, gap, bl_targets)
            region.gap_analysis = gap
        regions.append(region)

    return regions


def print_coverage_report(regions: List[CoverageRegion], verbose: bool = False) -> None:
    """Print the coverage analysis report."""

    # Statistics
    total_bytes = sum(r.size for r in regions)
    func_bytes = sum(r.size for r in regions if r.coverage_type == CoverageType.FUNCTION)
    data_bytes = sum(r.size for r in regions if r.coverage_type == CoverageType.DATA_VAR)
    uncovered_bytes = sum(r.size for r in regions if r.coverage_type == CoverageType.UNCOVERED)

    func_count = len([r for r in regions if r.coverage_type == CoverageType.FUNCTION and r.function_quality])
    gap_count = len([r for r in regions if r.coverage_type == CoverageType.UNCOVERED])

    # Actual gap regions (not individual bytes)
    gap_regions = [r for r in regions if r.coverage_type == CoverageType.UNCOVERED and r.gap_analysis]

    # Gaps that look like code (have high valid instruction ratio OR have prologues/BL targets)
    code_gaps = [r for r in gap_regions
                 if r.gap_analysis.looks_like_code
                 or r.gap_analysis.prologue_addresses
                 or r.gap_analysis.bl_target_addresses]

    # Function quality distribution
    qualities = [r.function_quality for r in regions
                 if r.function_quality is not None]
    good_funcs = len([q for q in qualities if q.quality_score >= 80])
    ok_funcs = len([q for q in qualities if 60 <= q.quality_score < 80])
    weak_funcs = len([q for q in qualities if 40 <= q.quality_score < 60])
    poor_funcs = len([q for q in qualities if q.quality_score < 40])

    print(f"\n{'='*70}")
    print(f"BYTE-LEVEL COVERAGE REPORT")
    print(f"{'='*70}")
    print(f"Total bytes analyzed: {total_bytes:,} ({total_bytes/(1024*1024):.1f} MB)")
    print()
    print(f"COVERAGE BREAKDOWN:")
    print(f"  Functions:  {func_bytes:,} bytes ({func_bytes*100/total_bytes:.1f}%)")
    print(f"  Data vars:  {data_bytes:,} bytes ({data_bytes*100/total_bytes:.1f}%)")
    print(f"  Uncovered:  {uncovered_bytes:,} bytes ({uncovered_bytes*100/total_bytes:.1f}%)")
    print()
    print(f"FUNCTION QUALITY ({func_count} functions):")
    print(f"  GOOD (80+):  {good_funcs} ({good_funcs*100/func_count:.1f}%)" if func_count else "  No functions")
    print(f"  OK (60-79):  {ok_funcs} ({ok_funcs*100/func_count:.1f}%)" if func_count else "")
    print(f"  WEAK (40-59): {weak_funcs} ({weak_funcs*100/func_count:.1f}%)" if func_count else "")
    print(f"  POOR (<40):  {poor_funcs} ({poor_funcs*100/func_count:.1f}%)" if func_count else "")
    print()
    print(f"UNCOVERED GAPS: {len(gap_regions)} contiguous regions")
    print(f"  Likely code: {len(code_gaps)} regions")

    # Show problematic gaps (likely code that wasn't detected)
    if code_gaps:
        print(f"\n{'='*70}")
        print(f"UNCOVERED REGIONS THAT LOOK LIKE CODE")
        print(f"{'='*70}")

        # Sort by size, largest first
        code_gaps.sort(key=lambda r: r.size, reverse=True)

        for i, region in enumerate(code_gaps[:20], 1):
            gap = region.gap_analysis
            print(f"\n[{i}] {region.start:#x} - {region.end:#x} ({region.size:,} bytes)")
            print(f"    Valid instruction ratio: {gap.valid_instruction_ratio:.1%}")
            print(f"    Diagnosis: {gap.diagnosis}")

            if gap.prologue_addresses:
                print(f"    Prologues at:")
                for addr in gap.prologue_addresses[:5]:
                    print(f"        {addr:#x}")
                if len(gap.prologue_addresses) > 5:
                    print(f"        ... and {len(gap.prologue_addresses) - 5} more")

            if gap.bl_target_addresses:
                print(f"    BL targets:")
                for addr in gap.bl_target_addresses[:5]:
                    print(f"        {addr:#x}")
                if len(gap.bl_target_addresses) > 5:
                    print(f"        ... and {len(gap.bl_target_addresses) - 5} more")

        if len(code_gaps) > 20:
            print(f"\n... and {len(code_gaps) - 20} more code-like gaps")

    # Show poor quality functions
    poor_quality = [r for r in regions
                    if r.function_quality and r.function_quality.quality_score < 40]

    if poor_quality:
        print(f"\n{'='*70}")
        print(f"POOR QUALITY FUNCTIONS (score < 40)")
        print(f"{'='*70}")

        poor_quality.sort(key=lambda r: r.function_quality.quality_score)

        for i, region in enumerate(poor_quality[:20], 1):
            q = region.function_quality
            print(f"\n[{i}] {q.address:#x} (score: {q.quality_score})")
            print(f"    Size: {q.size} bytes, Blocks: {q.block_count}")
            issues = []
            if q.starts_with_epilogue: issues.append("starts with epilogue")
            if q.too_small: issues.append("too small")
            if q.too_large: issues.append("too large")
            if q.overlaps_data: issues.append("overlaps data")
            if not q.has_prologue: issues.append("no prologue")
            if not q.has_callers: issues.append("no callers")
            if issues:
                print(f"    Issues: {', '.join(issues)}")

        if len(poor_quality) > 20:
            print(f"\n... and {len(poor_quality) - 20} more poor quality functions")


# ---------------------------------------------------------------------------
# Main
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
            print(f"  Waiting for: {task.progress}")
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


def main():
    if bn is None:
        print("Binary Ninja Python API not available")
        sys.exit(1)

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <firmware.bin> [code_end_address]")
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

    start = view.start
    end = code_end if code_end else view.end

    print(f"\nSweeping {start:#x} to {end:#x}...")
    regions = sweep_binary(view, start, end)

    print_coverage_report(regions)

    view.file.close()


if __name__ == "__main__":
    main()
