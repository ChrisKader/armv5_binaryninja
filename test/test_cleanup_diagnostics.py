"""
Cleanup diagnostics: analyse false removal patterns in CleanupInvalidFunctions.

This script loads a firmware binary, waits for analysis, then examines every
function to simulate what CleanupInvalidFunctions would do — but with full
diagnostic output.  It cross-references removal candidates against their
incoming code refs to quantify false-positive rates.

Run with:
    python -m pytest test/test_cleanup_diagnostics.py -s -v

Or as a standalone BN script (inside BN's Script Console or headless):
    import importlib, test.test_cleanup_diagnostics as d
    importlib.reload(d); d.run_on_view(bv)
"""
from __future__ import annotations

import struct
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import pytest

try:
    import binaryninja as bn
except ImportError:
    bn = None

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "nspire" / "cxii_cas_6.2.0.333" / "binaries"


# ---------------------------------------------------------------------------
# Heuristic checks — Python ports of the C++ logic in firmware_scans.cpp
# ---------------------------------------------------------------------------

def is_epilogue_first_instruction(word: int) -> bool:
    """Check if a 32-bit ARM word is a return instruction."""
    cond = (word >> 28) & 0xF
    # BX LR (any condition)
    if (word & 0x0FFFFFFF) == 0x012FFF1E:
        return True
    # MOV pc, lr
    if (word & 0x0FFFFFFF) == 0x01A0F00E:
        return True
    # POP / LDMIA sp!, {..., pc}
    if (word & 0x0FFF0000) == 0x08BD0000 and (word & (1 << 15)):
        return True
    # LDR pc, [sp], #imm
    if (word & 0x0FFF0000) == 0x049D0000 and ((word >> 12) & 0xF) == 0xF:
        return True
    return False


def quick_check_data_patterns(words: List[int]) -> Optional[str]:
    """Port of ValidateFunctionBody's first-8-instruction quick check."""
    eq_count = 0
    low_cond_count = 0
    branch_or_call_count = 0
    data_pattern_score = 0

    for word in words[:8]:
        if word == 0 or word == 0xFFFFFFFF:
            continue
        cond = (word >> 28) & 0xF
        if cond == 0x0:
            eq_count += 1
        if cond <= 0x3:
            low_cond_count += 1
        opcode = (word >> 24) & 0xFF
        if (opcode & 0x0F) in (0x0A, 0x0B):
            branch_or_call_count += 1
        if (word & 0x0FFFFFF0) in (0x012FFF10, 0x012FFF30):
            branch_or_call_count += 1
        rn = (word >> 16) & 0xF
        rd = (word >> 12) & 0xF
        rm = word & 0xF
        if rn == 0 and rd == 0 and rm == 0 and (word & 0x0E000000) == 0x00000000:
            data_pattern_score += 1

    if eq_count >= 3:
        return f"3+ EQ-condition in first 8 (eq={eq_count})"
    if low_cond_count >= 5:
        return f"5+ low-condition in first 8 (low={low_cond_count})"
    if branch_or_call_count == 0 and data_pattern_score >= 4:
        return f"no branches + {data_pattern_score} data-patterns in first 8"
    return None


def eq_ratio_check(words: List[int], limit: int = 512) -> Optional[str]:
    """Port of the EQ-condition ratio check (60% threshold)."""
    total_arm = 0
    eq_cond = 0
    for word in words[:limit]:
        if word == 0 or word == 0xFFFFFFFF:
            continue
        total_arm += 1
        if (word >> 28) & 0xF == 0x0:
            eq_cond += 1
    if total_arm >= 4:
        ratio = eq_cond / total_arm
        if ratio >= 0.6:
            return f"60%+ EQ-condition ({eq_cond}/{total_arm} = {ratio:.0%})"
    return None


def looks_like_string(data: bytes, min_len: int = 2, min_ratio: float = 0.70) -> bool:
    """Port of StringDetector::LooksLikeNullTerminatedString."""
    if len(data) < 2:
        return False

    def is_printable(c):
        return (0x20 <= c <= 0x7E) or c in (0x09, 0x0A, 0x0D)

    # Check 1: null-terminated string
    for i, b in enumerate(data):
        if b == 0x00 and i >= min_len:
            printable = sum(1 for c in data[:i] if is_printable(c))
            if printable / i >= min_ratio:
                return True
            break

    # Check 4: first 16 bytes mostly printable with a null
    check = data[:16]
    printable = sum(1 for c in check if is_printable(c))
    nulls = sum(1 for c in check if c == 0)
    non_null = len(check) - nulls
    if non_null >= 4 and 1 <= nulls <= 4:
        if printable / non_null >= 0.80:
            return True

    return False


# ---------------------------------------------------------------------------
# Diagnostic data structures
# ---------------------------------------------------------------------------

@dataclass
class FunctionDiag:
    address: int
    size: int
    block_count: int
    has_callers: bool
    caller_count: int
    has_return: bool
    first_word: int
    is_epilogue_start: bool
    removal_reason: Optional[str] = None
    would_remove: bool = False
    in_bn_string: bool = False
    looks_like_string: bool = False
    body_fail: Optional[str] = None


# ---------------------------------------------------------------------------
# Main diagnostic function — works on any BinaryView
# ---------------------------------------------------------------------------

def run_on_view(view, logger=None):
    """Run cleanup diagnostics on a BinaryView. Can be called from BN console."""
    if logger is None:
        # Use Binary Ninja's logging API — messages appear in BN's Log console
        # and are persisted to the log file.
        from binaryninja.log import log_info, log_warn

        class BNLogger:
            def log(self, msg): log_info(msg)
            def info(self, msg): log_info(msg)
            def warn(self, msg): log_warn(msg)

        logger = BNLogger()

    image_start = view.start
    image_end = view.end
    all_data = view.read(image_start, image_end - image_start)
    if not all_data:
        logger.log("ERROR: Could not read binary data")
        return

    functions = list(view.functions)
    logger.info(f"Analysing {len(functions)} functions ({image_start:#x} - {image_end:#x})")

    diags: List[FunctionDiag] = []
    reason_counts: Counter = Counter()
    reason_with_callers: Counter = Counter()
    reason_without_callers: Counter = Counter()

    for func in functions:
        start = func.start
        blocks = list(func.basic_blocks)
        highest = func.highest_address if blocks else start
        arch = func.arch or view.arch
        instr_size = arch.default_int_size if arch else 4
        size = (highest - start + instr_size) if highest >= start else 0

        # Read first word
        offset = start - image_start
        if offset + 4 > len(all_data):
            continue
        first_word = struct.unpack_from("<I", all_data, offset)[0]

        # Check callers — get_code_refs returns a generator, so materialize it
        refs = list(view.get_code_refs(start))
        caller_count = len(refs)
        has_callers = caller_count > 0

        # Check return
        has_return = any(block.can_exit for block in blocks)

        # Epilogue check
        is_epi = is_epilogue_first_instruction(first_word)

        # BN string check
        bn_strings = view.get_strings(start, 1)
        in_bn_string = bool(bn_strings)

        # Our string heuristic check
        search_len = min(256, len(all_data) - offset)
        like_string = looks_like_string(all_data[offset:offset + search_len])

        # Quick data pattern check
        words = []
        for i in range(min(8, search_len // 4)):
            w = struct.unpack_from("<I", all_data, offset + i * 4)[0]
            words.append(w)

        quick_fail = quick_check_data_patterns(words)

        # EQ ratio check (first 512 instructions = 2KB)
        all_words = []
        body_len = min(size, 2048)
        for i in range(body_len // 4):
            if offset + (i + 1) * 4 <= len(all_data):
                w = struct.unpack_from("<I", all_data, offset + i * 4)[0]
                all_words.append(w)
        eq_fail = eq_ratio_check(all_words)

        # Determine what would happen
        removal_reason = None
        would_remove = False

        if not blocks:
            removal_reason = "no basic blocks"
            would_remove = True
        elif has_callers:
            # Protected by caller check — would NOT be removed
            removal_reason = None
            would_remove = False
        elif in_bn_string:
            removal_reason = "inside BN string"
            would_remove = True
        elif is_epi:
            removal_reason = "epilogue first instruction"
            would_remove = True
        elif quick_fail:
            removal_reason = f"body: {quick_fail}"
            would_remove = True
        elif eq_fail:
            removal_reason = f"body: {eq_fail}"
            would_remove = True
        # Note: we can't fully replicate ValidateFunctionBody's BB decode walk
        # from Python — BN already decoded it. But we can flag the heuristic
        # checks we CAN replicate.

        # Also check what the OLD code would have done (with LooksLikeString)
        old_would_remove_string = like_string and not has_callers

        d = FunctionDiag(
            address=start,
            size=size,
            block_count=len(blocks),
            has_callers=has_callers,
            caller_count=caller_count,
            has_return=has_return,
            first_word=first_word,
            is_epilogue_start=is_epi,
            removal_reason=removal_reason,
            would_remove=would_remove,
            in_bn_string=in_bn_string,
            looks_like_string=like_string,
            body_fail=quick_fail or eq_fail,
        )
        diags.append(d)

        if would_remove and removal_reason:
            reason_counts[removal_reason] += 1
            if has_callers:
                reason_with_callers[removal_reason] += 1
            else:
                reason_without_callers[removal_reason] += 1

    # ---------------------------------------------------------------------------
    # Report
    # ---------------------------------------------------------------------------
    logger.info("=" * 70)
    logger.info("CLEANUP DIAGNOSTICS REPORT")
    logger.info("=" * 70)

    total = len(diags)
    with_callers = sum(1 for d in diags if d.has_callers)
    would_remove_count = sum(1 for d in diags if d.would_remove)
    epilogue_starts = sum(1 for d in diags if d.is_epilogue_start)
    no_return = sum(1 for d in diags if not d.has_return and d.block_count > 0)
    old_string_removes = sum(1 for d in diags if d.looks_like_string and not d.has_callers)

    logger.info(f"Total functions:              {total}")
    logger.info(f"  With callers (protected):   {with_callers}")
    logger.info(f"  Without callers:            {total - with_callers}")
    logger.info(f"  Epilogue-first-instruction: {epilogue_starts}")
    logger.info(f"  No return block:            {no_return}")
    logger.info(f"")
    logger.info(f"Would remove (new logic):     {would_remove_count}")
    logger.info(f"OLD LooksLikeString removes:  {old_string_removes} (now skipped)")

    logger.info(f"")
    logger.info("--- Removal breakdown (new logic) ---")
    for reason, count in reason_counts.most_common():
        logger.info(f"  {count:6d}  {reason}")

    # Functions that WOULD HAVE been removed by old code but are now protected
    protected_by_callers = [d for d in diags if d.has_callers and (
        d.body_fail or d.looks_like_string or d.is_epilogue_start)]
    logger.info(f"")
    logger.info(f"--- Protected by caller check (would have been removed) ---")
    logger.info(f"  Total protected: {len(protected_by_callers)}")
    protect_reasons: Counter = Counter()
    for d in protected_by_callers:
        if d.looks_like_string:
            protect_reasons["old: looks like string"] += 1
        if d.body_fail:
            protect_reasons[f"old: {d.body_fail}"] += 1
        if d.is_epilogue_start:
            protect_reasons["epilogue start (has callers)"] += 1
    for reason, count in protect_reasons.most_common():
        logger.info(f"  {count:6d}  {reason}")

    # Show sample false positives — functions with callers that look like strings
    string_fp = [d for d in diags if d.looks_like_string and d.has_callers]
    if string_fp:
        logger.info(f"")
        logger.info(f"--- Sample: functions WITH callers that LooksLikeString flags ({len(string_fp)} total) ---")
        for d in string_fp[:20]:
            logger.info(
                f"  {d.address:#010x}  callers={d.caller_count:3d}  "
                f"size={d.size:5d}  blocks={d.block_count:3d}  "
                f"first={d.first_word:#010x}  return={'Y' if d.has_return else 'N'}"
            )

    # Show sample epilogue functions
    epi_funcs = [d for d in diags if d.is_epilogue_start]
    if epi_funcs:
        logger.info(f"")
        logger.info(f"--- Sample: epilogue-first-instruction functions ({len(epi_funcs)} total) ---")
        for d in epi_funcs[:20]:
            logger.info(
                f"  {d.address:#010x}  callers={d.caller_count:3d}  "
                f"first={d.first_word:#010x}  "
                f"{'PROTECTED (has callers)' if d.has_callers else 'REMOVE'}"
            )

    # Show functions with body heuristic failures but callers
    body_fail_with_callers = [d for d in diags if d.body_fail and d.has_callers]
    if body_fail_with_callers:
        logger.info(f"")
        logger.info(f"--- Sample: body-fail WITH callers (protected) ({len(body_fail_with_callers)} total) ---")
        for d in body_fail_with_callers[:20]:
            logger.info(
                f"  {d.address:#010x}  callers={d.caller_count:3d}  "
                f"size={d.size:5d}  fail={d.body_fail}"
            )

    logger.info("=" * 70)
    return diags


# ---------------------------------------------------------------------------
# pytest integration
# ---------------------------------------------------------------------------

@pytest.mark.requires_binaryninja
class TestCleanupDiagnostics:

    @pytest.fixture(scope="class")
    def firmware_view(self):
        if bn is None:
            pytest.skip("Binary Ninja Python API not available")

        # Allow override via environment
        bin_path = os.environ.get("ARMV5_DIAG_BINARY")
        if bin_path:
            binary_path = Path(bin_path)
        else:
            binary_path = DATA_DIR / "nspire.bin"

        if not binary_path.exists():
            pytest.skip(f"Missing binary: {binary_path}")
        if "ARMv5 Firmware" not in bn.BinaryViewType:
            pytest.skip("ARMv5 Firmware view type not available")

        view_type = bn.BinaryViewType["ARMv5 Firmware"]
        file_metadata = bn.FileMetadata(str(binary_path))
        view = view_type.open(str(binary_path), file_metadata=file_metadata)
        if view is None:
            file_metadata.close()
            pytest.skip(f"Failed to open {binary_path}")

        view.update_analysis_and_wait()

        # Wait for the ARMv5 firmware scan background task to complete.
        # The scan job runs asynchronously after update_analysis_and_wait() returns.
        # We use the BackgroundTask API to find and wait for the specific task.
        import time
        from binaryninja.plugin import BackgroundTask
        from binaryninja.enums import AnalysisState

        def find_armv5_task():
            """Find the ARMv5 firmware scan background task if running."""
            for task in BackgroundTask:
                progress = task.progress or ""
                if "ARMv5" in progress and not task.finished:
                    return task
            return None

        # Wait up to 10 minutes for the firmware scan to complete
        timeout_seconds = 600
        start_time = time.time()
        poll_interval = 0.5

        while time.time() - start_time < timeout_seconds:
            # Check if there's an ARMv5 task running
            task = find_armv5_task()
            if task is not None:
                # Found the task - wait for it to finish
                while not task.finished:
                    if time.time() - start_time > timeout_seconds:
                        raise TimeoutError(
                            f"ARMv5 firmware scan timed out after {timeout_seconds}s. "
                            f"Last progress: {task.progress}"
                        )
                    time.sleep(poll_interval)
                # Task finished - wait for BN's analysis to settle
                view.update_analysis_and_wait()
                break

            # No ARMv5 task found - check if analysis is idle
            if view.analysis_state == AnalysisState.IdleState:
                # Analysis is idle and no ARMv5 task - we may have missed it or it completed
                # Wait a bit longer to see if a new task spawns
                time.sleep(1.0)
                task = find_armv5_task()
                if task is None:
                    # Still no task and analysis is idle - assume scan completed
                    break

            time.sleep(poll_interval)
        else:
            raise TimeoutError(
                f"Timed out waiting for ARMv5 firmware scan after {timeout_seconds}s"
            )

        yield view
        view.file.close()

    def test_cleanup_diagnostics(self, firmware_view):
        """Run full cleanup diagnostics and report findings."""
        diags = run_on_view(firmware_view)
        assert diags, "Should have analysed at least some functions"

        # Verify no functions with 3+ callers would be removed
        high_caller_removals = [
            d for d in diags if d.would_remove and d.caller_count >= 3
        ]
        assert len(high_caller_removals) == 0, (
            f"{len(high_caller_removals)} functions with 3+ callers would be removed: "
            + ", ".join(f"{d.address:#x}" for d in high_caller_removals[:10])
        )

    def test_no_prologue_functions_removed(self, firmware_view):
        """Functions starting with PUSH {regs, lr} should never be removed."""
        diags = run_on_view(firmware_view)

        prologue_removals = []
        for d in diags:
            if not d.would_remove:
                continue
            # Check for PUSH/STMFD pattern
            w = d.first_word
            if (w & 0x0FFF0000) == 0x092D0000 and (w & (1 << 14)):
                # STMFD sp!, {..., lr}
                prologue_removals.append(d)

        assert len(prologue_removals) == 0, (
            f"{len(prologue_removals)} functions with PUSH {{..., lr}} would be removed: "
            + ", ".join(f"{d.address:#x}" for d in prologue_removals[:10])
        )

    def test_string_heuristic_false_positives(self, firmware_view):
        """Quantify LooksLikeString false positives on real code."""
        diags = run_on_view(firmware_view)

        # Functions with callers that look like strings = false positives
        fp = [d for d in diags if d.looks_like_string and d.has_callers]
        total_with_callers = sum(1 for d in diags if d.has_callers)

        if total_with_callers > 0:
            fp_rate = len(fp) / total_with_callers
            print(f"\nLooksLikeString false-positive rate on called functions: "
                  f"{len(fp)}/{total_with_callers} ({fp_rate:.1%})")
            # The old heuristic should have a high FP rate — that's why we removed it
            # We're documenting the rate, not asserting a threshold

    def test_epilogue_detection(self, firmware_view):
        """Verify epilogue-first-instruction functions are correctly identified."""
        diags = run_on_view(firmware_view)

        epi_funcs = [d for d in diags if d.is_epilogue_start]
        epi_with_callers = [d for d in epi_funcs if d.has_callers]
        epi_without = [d for d in epi_funcs if not d.has_callers]

        print(f"\nEpilogue-first functions: {len(epi_funcs)}")
        print(f"  With callers (protected): {len(epi_with_callers)}")
        print(f"  Without callers (removed): {len(epi_without)}")

        # Epilogue functions with callers should be protected (they're BX LR stubs)
        for d in epi_with_callers:
            assert not d.would_remove, (
                f"Epilogue function {d.address:#x} with {d.caller_count} callers "
                f"would be removed"
            )
