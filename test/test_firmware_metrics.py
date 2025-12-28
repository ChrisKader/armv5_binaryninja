from __future__ import annotations

import ctypes
import heapq
import os
import time
from pathlib import Path
from typing import Iterable, List, Sequence

import pytest

try:
    import binaryninja as bn  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    bn = None

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_BINARIES = ("btrom.bin", "bootloader.bin", "osloader.bin")
LARGE_BINARIES = ("nspire.bin",)


def _resolve_binaries() -> List[Path]:
    env_list = os.environ.get("ARMV5_FIRMWARE_METRICS_BINARIES")
    include_large = os.environ.get("ARMV5_FIRMWARE_METRICS_INCLUDE_LARGE") == "1"

    paths: List[Path] = []
    if env_list:
        for entry in env_list.split(","):
            name = entry.strip()
            if not name:
                continue
            candidate = Path(name)
            if not candidate.is_absolute():
                candidate = DATA_DIR / candidate
            paths.append(candidate)
    else:
        basenames = list(DEFAULT_BINARIES)
        if include_large:
            basenames.extend(LARGE_BINARIES)
        paths = [DATA_DIR / name for name in basenames]

    return [path for path in paths if path.exists()]


def _percentile(sorted_values: Sequence[int], pct: float) -> int:
    if not sorted_values:
        return 0
    if pct <= 0:
        return sorted_values[0]
    if pct >= 100:
        return sorted_values[-1]
    idx = int(round((pct / 100) * (len(sorted_values) - 1)))
    return sorted_values[idx]


def _bucket_counts(values: Iterable[int], edges: Sequence[int]) -> List[int]:
    counts = [0] * (len(edges) + 1)
    for value in values:
        placed = False
        for idx, edge in enumerate(edges):
            if value <= edge:
                counts[idx] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1
    return counts


def _collect_function_sizes(view) -> tuple[int, List[int], List[tuple[int, int]]]:
    func_sizes: List[int] = []
    top_functions: List[tuple[int, int]] = []

    count = ctypes.c_ulonglong(0)
    func_list = bn.core.BNGetAnalysisFunctionList(view.handle, count)
    if not func_list:
        return 0, func_sizes, top_functions
    try:
        for i in range(count.value):
            func = bn.core.BNNewFunctionReference(func_list[i])
            if not func:
                continue
            try:
                start = bn.core.BNGetFunctionStart(func)
                range_count = ctypes.c_ulonglong(0)
                ranges = bn.core.BNGetFunctionAddressRanges(func, range_count)
                size = 0
                if ranges:
                    for j in range(range_count.value):
                        size += ranges[j].end - ranges[j].start
                    bn.core.BNFreeAddressRanges(ranges)
                func_sizes.append(size)
                entry = (size, start)
                if len(top_functions) < 10:
                    heapq.heappush(top_functions, entry)
                elif size > top_functions[0][0]:
                    heapq.heapreplace(top_functions, entry)
            finally:
                bn.core.BNFreeFunction(func)
    finally:
        bn.core.BNFreeFunctionList(func_list, count.value)

    return count.value, func_sizes, top_functions


_BINARIES = _resolve_binaries()
if not _BINARIES:
    _BINARIES = [
        pytest.param(DATA_DIR / "missing.bin", marks=pytest.mark.skip(reason="No test binaries available"))
    ]


@pytest.mark.requires_binaryninja
@pytest.mark.parametrize("binary_path", _BINARIES, ids=lambda p: p.name)
def test_firmware_analysis_metrics(binary_path: Path) -> None:
    if bn is None:
        pytest.skip("Binary Ninja Python API not available")
    if not binary_path.exists():
        pytest.skip(f"Missing test binary: {binary_path}")
    if "ARMv5 Firmware" not in bn.BinaryViewType:
        pytest.skip("ARMv5 Firmware view type not available (is the plugin installed?)")

    view_type = bn.BinaryViewType["ARMv5 Firmware"]
    file_metadata = bn.FileMetadata(str(binary_path))
    open_start = time.perf_counter()
    view = view_type.open(str(binary_path), file_metadata=file_metadata)
    open_time = time.perf_counter() - open_start
    if view is None:
        file_metadata.close()
        pytest.skip(f"Failed to open {binary_path} as ARMv5 Firmware view")

    with view:

        analysis_start = time.perf_counter()
        view.update_analysis_and_wait()
        analysis_time = time.perf_counter() - analysis_start

        sections_start = time.perf_counter()
        section_entries = []
        total_section_bytes = 0
        sections_map = view.sections
        for section in sections_map.values():
            semantics = section.semantics.name if hasattr(section.semantics, "name") else str(section.semantics)
            section_entries.append(
                (section.name, section.start, section.length, section.end, semantics, section.auto_defined)
            )
            total_section_bytes += section.length
        section_entries.sort(key=lambda entry: entry[1])
        del sections_map
        sections_time = time.perf_counter() - sections_start

        funcs_start = time.perf_counter()
        func_count, func_sizes, top_functions = _collect_function_sizes(view)
        funcs_time = time.perf_counter() - funcs_start

        file_size = binary_path.stat().st_size
        print("")
        print(f"Firmware metrics for {binary_path.name}")
        print(f"file_size: 0x{file_size:x} ({file_size})")
        print(f"timing.open_view_sec: {open_time:.3f}")
        print(f"timing.analysis_sec: {analysis_time:.3f}")
        print(f"timing.sections_sec: {sections_time:.3f}")
        print(f"timing.functions_sec: {funcs_time:.3f}")

        print(f"sections.count: {len(section_entries)}")
        print(f"sections.total_bytes: 0x{total_section_bytes:x} ({total_section_bytes})")
        for name, start, length, end, semantics, auto_defined in section_entries:
            print(
                "section "
                f"{name}: "
                f"start=0x{start:x} "
                f"len=0x{length:x} ({length}) "
                f"end=0x{end:x} "
                f"semantics={semantics} "
                f"auto={auto_defined}"
            )

        print(f"functions.count: {func_count}")
        if func_sizes:
            sizes_sorted = sorted(func_sizes)
            func_total = sum(func_sizes)
            func_mean = func_total / len(func_sizes)
            func_median = _percentile(sizes_sorted, 50)
            func_p90 = _percentile(sizes_sorted, 90)
            func_p99 = _percentile(sizes_sorted, 99)
            zero_count = sum(1 for size in func_sizes if size == 0)
            print(f"functions.total_bytes: 0x{func_total:x} ({func_total})")
            print(f"functions.size.min: 0x{sizes_sorted[0]:x} ({sizes_sorted[0]})")
            print(f"functions.size.max: 0x{sizes_sorted[-1]:x} ({sizes_sorted[-1]})")
            print(f"functions.size.mean: 0x{int(func_mean):x} ({func_mean:.2f})")
            print(f"functions.size.median: 0x{func_median:x} ({func_median})")
            print(f"functions.size.p90: 0x{func_p90:x} ({func_p90})")
            print(f"functions.size.p99: 0x{func_p99:x} ({func_p99})")
            print(f"functions.size.zero: {zero_count}")

            bucket_edges = [0x20, 0x80, 0x200, 0x800, 0x2000, 0x8000]
            bucket_labels = [f"<=0x{edge:x}" for edge in bucket_edges]
            bucket_labels.append(f">0x{bucket_edges[-1]:x}")
            bucket_counts = _bucket_counts(sizes_sorted, bucket_edges)
            bucket_summary = ", ".join(
                f"{label}: {count}" for label, count in zip(bucket_labels, bucket_counts)
            )
            print(f"functions.size.buckets: {bucket_summary}")

            top_functions.sort(key=lambda entry: entry[0], reverse=True)
            print("functions.largest:")
            for size, start in top_functions:
                print(f"  0x{start:x} size=0x{size:x} ({size})")
        else:
            print("functions.size: no functions discovered")

        assert len(section_entries) >= 3
        assert func_count > 0
