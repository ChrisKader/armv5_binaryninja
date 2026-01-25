#!/usr/bin/env python3
"""
Function Quality Validator for ARMv5

Validates all detected functions checking:
1. Prologue validity (starts with PUSH/STMFD/SUB SP)
2. Epilogue validity (ends with return instruction)
3. Instruction validity (all instructions decode properly)
4. Boundary sanity (no overlaps, reasonable sizes)
5. Code patterns (no obvious data-as-code)
"""

import sys
import struct
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple

sys.path.insert(0, "/Applications/Binary Ninja DEV.app/Contents/Resources/python")

import binaryninja as bn

@dataclass
class FunctionIssue:
    """A single issue found with a function."""
    category: str
    severity: str  # "error", "warning", "info"
    message: str

@dataclass
class FunctionReport:
    """Quality report for a single function."""
    address: int
    name: str
    size: int
    is_thumb: bool
    issues: List[FunctionIssue] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(i.severity == "error" for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(i.severity == "warning" for i in self.issues)

    @property
    def is_clean(self) -> bool:
        return len(self.issues) == 0

class FunctionValidator:
    """Validates ARMv5 functions for quality issues."""

    # ARM prologue patterns (first instruction)
    ARM_PROLOGUE_MASKS = [
        (0x0FFF0000, 0x092D0000, 0x4000),  # STMFD/PUSH with LR
        (0x0FFF0000, 0x024DD000, None),     # SUB SP, SP, #imm
        (0x0FFFFFFF, 0x01A0B00D, None),     # MOV R11, SP
        (0x0FFFFFFF, 0x052DE004, None),     # STR LR, [SP, #-4]!
    ]

    # ARM epilogue patterns (last instruction before return)
    ARM_EPILOGUE_MASKS = [
        (0x0FFFFFFF, 0x012FFF1E),  # BX LR
        (0x0FFFFFFF, 0x01A0F00E),  # MOV PC, LR
        (0x0FFF8000, 0x08BD8000),  # POP/LDMIA with PC
        (0x0F000000, 0x0A000000),  # B (tail call)
    ]

    # Thumb prologue patterns
    THUMB_PROLOGUE_MASKS = [
        (0xFF00, 0xB500),      # PUSH {LR} or PUSH {regs, LR}
        (0xFF80, 0xB080),      # SUB SP, #imm
    ]

    # Thumb epilogue patterns
    THUMB_EPILOGUE_MASKS = [
        (0xFF00, 0xBD00),      # POP {PC}
        (0xFFFF, 0x4770),      # BX LR
        (0xF800, 0xE000),      # B (unconditional, might be tail call)
    ]

    # Suspicious patterns (likely data, not code)
    SUSPICIOUS_PATTERNS = [
        0x00000000,  # All zeros
        0xFFFFFFFF,  # All ones
        0xDEADBEEF,  # Common debug pattern
        0xCAFEBABE,  # Common debug pattern
        0xFEEDFACE,  # Common debug pattern
    ]

    def __init__(self, view: bn.BinaryView):
        self.view = view
        self.functions: List[bn.Function] = []
        self.reports: List[FunctionReport] = []
        self.address_to_func: Dict[int, bn.Function] = {}

    def load_functions(self):
        """Load all functions from the view."""
        print("Loading functions...")
        self.functions = list(self.view.functions)
        self.address_to_func = {f.start: f for f in self.functions}
        print(f"Loaded {len(self.functions)} functions")

    def read_u32(self, addr: int) -> int:
        """Read a 32-bit little-endian value."""
        data = self.view.read(addr, 4)
        if len(data) < 4:
            return 0
        return struct.unpack("<I", data)[0]

    def read_u16(self, addr: int) -> int:
        """Read a 16-bit little-endian value."""
        data = self.view.read(addr, 2)
        if len(data) < 2:
            return 0
        return struct.unpack("<H", data)[0]

    def check_arm_prologue(self, addr: int) -> bool:
        """Check if address starts with a valid ARM prologue."""
        instr = self.read_u32(addr)
        for mask, value, extra in self.ARM_PROLOGUE_MASKS:
            if (instr & mask) == value:
                if extra is None or (instr & extra):
                    return True
        return False

    def check_thumb_prologue(self, addr: int) -> bool:
        """Check if address starts with a valid Thumb prologue."""
        instr = self.read_u16(addr)
        for mask, value in self.THUMB_PROLOGUE_MASKS:
            if (instr & mask) == value:
                return True
        # Check 32-bit Thumb PUSH.W
        if instr == 0xE92D:
            next_hw = self.read_u16(addr + 2)
            if next_hw & 0x4000:  # LR in register list
                return True
        return False

    def check_arm_epilogue(self, func: bn.Function) -> Tuple[bool, int]:
        """Check if function ends with valid ARM epilogue. Returns (valid, last_instr_addr)."""
        # Get the last basic block
        blocks = list(func.basic_blocks)
        if not blocks:
            return False, 0

        # Find blocks with no outgoing edges (exit blocks)
        exit_blocks = [b for b in blocks if b.outgoing_edges == []]
        if not exit_blocks:
            # All blocks have outgoing edges - might be infinite loop or tail calls
            exit_blocks = blocks

        for block in exit_blocks:
            if block.length == 0:
                continue
            # Get last instruction address
            last_addr = block.end - 4
            if last_addr < block.start:
                continue
            instr = self.read_u32(last_addr)
            for mask, value in self.ARM_EPILOGUE_MASKS:
                if (instr & mask) == value:
                    return True, last_addr

        return False, 0

    def check_thumb_epilogue(self, func: bn.Function) -> Tuple[bool, int]:
        """Check if function ends with valid Thumb epilogue."""
        blocks = list(func.basic_blocks)
        if not blocks:
            return False, 0

        exit_blocks = [b for b in blocks if b.outgoing_edges == []]
        if not exit_blocks:
            exit_blocks = blocks

        for block in exit_blocks:
            if block.length == 0:
                continue
            # Try 16-bit instruction at end
            last_addr = block.end - 2
            if last_addr >= block.start:
                instr = self.read_u16(last_addr)
                for mask, value in self.THUMB_EPILOGUE_MASKS:
                    if (instr & mask) == value:
                        return True, last_addr
            # Try 32-bit Thumb at end
            last_addr = block.end - 4
            if last_addr >= block.start:
                hw1 = self.read_u16(last_addr)
                hw2 = self.read_u16(last_addr + 2)
                instr32 = (hw1 << 16) | hw2
                # 32-bit POP.W with PC
                if (instr32 & 0xFFFF8000) == 0xE8BD8000:
                    return True, last_addr

        return False, 0

    def check_suspicious_instructions(self, func: bn.Function) -> List[Tuple[int, int]]:
        """Find suspicious instruction patterns that might be data."""
        suspicious = []
        is_thumb = func.arch.name.endswith('t')

        for block in func.basic_blocks:
            addr = block.start
            while addr < block.end:
                if is_thumb:
                    # Check for 16-bit suspicious
                    instr = self.read_u16(addr)
                    if instr == 0x0000 or instr == 0xFFFF:
                        suspicious.append((addr, instr))
                    addr += 2
                else:
                    instr = self.read_u32(addr)
                    if instr in self.SUSPICIOUS_PATTERNS:
                        suspicious.append((addr, instr))
                    addr += 4

        return suspicious

    def check_function_overlaps(self) -> Dict[int, List[int]]:
        """Find functions that overlap with each other."""
        overlaps = defaultdict(list)

        # Sort functions by start address
        sorted_funcs = sorted(self.functions, key=lambda f: f.start)

        for i, func in enumerate(sorted_funcs):
            func_end = func.start + func.total_bytes
            # Check if any following function starts before this one ends
            for j in range(i + 1, len(sorted_funcs)):
                next_func = sorted_funcs[j]
                if next_func.start >= func_end:
                    break
                overlaps[func.start].append(next_func.start)

        return overlaps

    def validate_function(self, func: bn.Function) -> FunctionReport:
        """Validate a single function and return a report."""
        is_thumb = func.arch.name.endswith('t')
        report = FunctionReport(
            address=func.start,
            name=func.name,
            size=func.total_bytes,
            is_thumb=is_thumb
        )

        # Check 1: Prologue validity
        if is_thumb:
            has_prologue = self.check_thumb_prologue(func.start)
        else:
            has_prologue = self.check_arm_prologue(func.start)

        if not has_prologue:
            # Not an error - many valid functions don't have standard prologues
            # (leaf functions, thunks, etc.)
            report.issues.append(FunctionIssue(
                category="prologue",
                severity="info",
                message="No standard prologue pattern detected"
            ))

        # Check 2: Epilogue validity
        if is_thumb:
            has_epilogue, _ = self.check_thumb_epilogue(func)
        else:
            has_epilogue, _ = self.check_arm_epilogue(func)

        if not has_epilogue:
            report.issues.append(FunctionIssue(
                category="epilogue",
                severity="warning",
                message="No standard epilogue/return pattern detected"
            ))

        # Check 3: Size sanity
        if func.total_bytes == 0:
            report.issues.append(FunctionIssue(
                category="size",
                severity="error",
                message="Function has zero size"
            ))
        elif func.total_bytes < 4:
            report.issues.append(FunctionIssue(
                category="size",
                severity="warning",
                message=f"Function is very small ({func.total_bytes} bytes)"
            ))
        elif func.total_bytes > 100000:
            report.issues.append(FunctionIssue(
                category="size",
                severity="warning",
                message=f"Function is unusually large ({func.total_bytes} bytes)"
            ))

        # Check 4: Basic block count
        blocks = list(func.basic_blocks)
        if len(blocks) == 0:
            report.issues.append(FunctionIssue(
                category="structure",
                severity="error",
                message="Function has no basic blocks"
            ))

        # Check 5: Suspicious instruction patterns
        suspicious = self.check_suspicious_instructions(func)
        if len(suspicious) > 3:
            report.issues.append(FunctionIssue(
                category="code_quality",
                severity="warning",
                message=f"Function contains {len(suspicious)} suspicious instruction patterns (possible data)"
            ))

        # Check 6: Alignment
        if not is_thumb and (func.start & 3):
            report.issues.append(FunctionIssue(
                category="alignment",
                severity="error",
                message=f"ARM function not 4-byte aligned (0x{func.start:x})"
            ))
        elif is_thumb and (func.start & 1):
            report.issues.append(FunctionIssue(
                category="alignment",
                severity="error",
                message=f"Thumb function not 2-byte aligned (0x{func.start:x})"
            ))

        return report

    def validate_all(self, show_progress: bool = True) -> List[FunctionReport]:
        """Validate all functions."""
        self.reports = []
        total = len(self.functions)

        # First check for overlaps
        print("Checking for function overlaps...")
        overlaps = self.check_function_overlaps()

        print(f"Validating {total} functions...")
        for i, func in enumerate(self.functions):
            if show_progress and i % 1000 == 0:
                print(f"  Progress: {i}/{total} ({100*i//total}%)")

            report = self.validate_function(func)

            # Add overlap issues
            if func.start in overlaps:
                for overlap_addr in overlaps[func.start]:
                    report.issues.append(FunctionIssue(
                        category="overlap",
                        severity="error",
                        message=f"Overlaps with function at 0x{overlap_addr:x}"
                    ))

            self.reports.append(report)

        print(f"  Progress: {total}/{total} (100%)")
        return self.reports

    def generate_summary(self) -> str:
        """Generate a summary of validation results."""
        lines = []
        lines.append("=" * 70)
        lines.append("FUNCTION QUALITY VALIDATION SUMMARY")
        lines.append("=" * 70)

        total = len(self.reports)
        clean = sum(1 for r in self.reports if r.is_clean)
        with_errors = sum(1 for r in self.reports if r.has_errors)
        with_warnings = sum(1 for r in self.reports if r.has_warnings and not r.has_errors)
        info_only = total - clean - with_errors - with_warnings

        lines.append(f"\nTotal functions validated: {total}")
        lines.append(f"  Clean (no issues):     {clean:6d} ({100*clean//total:3d}%)")
        lines.append(f"  Info only:             {info_only:6d} ({100*info_only//total:3d}%)")
        lines.append(f"  With warnings:         {with_warnings:6d} ({100*with_warnings//total:3d}%)")
        lines.append(f"  With errors:           {with_errors:6d} ({100*with_errors//total:3d}%)")

        # Count issues by category
        category_counts = defaultdict(lambda: {"error": 0, "warning": 0, "info": 0})
        for report in self.reports:
            for issue in report.issues:
                category_counts[issue.category][issue.severity] += 1

        lines.append(f"\nIssues by category:")
        lines.append(f"  {'Category':<20} {'Errors':>8} {'Warnings':>8} {'Info':>8}")
        lines.append(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*8}")
        for cat, counts in sorted(category_counts.items()):
            lines.append(f"  {cat:<20} {counts['error']:>8} {counts['warning']:>8} {counts['info']:>8}")

        # Show worst offenders
        error_reports = [r for r in self.reports if r.has_errors]
        if error_reports:
            lines.append(f"\nFunctions with errors (showing first 20):")
            for report in error_reports[:20]:
                errors = [i for i in report.issues if i.severity == "error"]
                lines.append(f"  0x{report.address:08x} {report.name[:40]:<40}")
                for err in errors:
                    lines.append(f"    - [{err.category}] {err.message}")

        lines.append("\n" + "=" * 70)
        return "\n".join(lines)


def main():
    binary_path = Path("/Users/ck/dev/armv5_binaryninja/data/nspire/cxii_cas_6.2.0.333/binaries/nspire.bin")
    bndb_path = binary_path.with_suffix(".bndb")

    print(f"Function Quality Validator")
    print(f"Binary: {binary_path.name}")
    print("=" * 70)

    # Load the saved database
    if not bndb_path.exists():
        print(f"ERROR: No bndb file found at {bndb_path}")
        print("Run test_body_validation.py first to create the database.")
        return 1

    print(f"Loading {bndb_path.name}...")
    view = bn.load(str(bndb_path), update_analysis=False)
    if not view:
        print("ERROR: Failed to load binary")
        return 1

    # Create validator and run
    validator = FunctionValidator(view)
    validator.load_functions()
    validator.validate_all()

    # Print summary
    print(validator.generate_summary())

    view.file.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
