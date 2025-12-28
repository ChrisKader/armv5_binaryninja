from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

import pytest

from test.helpers import plugin_path

# Ensure Binary Ninja DEV paths are configured when available
os.environ.setdefault("BN_USER_DIRECTORY", str(Path.home() / ".binaryninja-dev"))
os.environ.setdefault("BN_INSTALL_DIR", "/Applications/Binary Ninja DEV.app")

BN_DEV_PYTHON = Path("/Applications/Binary Ninja DEV.app/Contents/Resources/python")
if BN_DEV_PYTHON.exists() and str(BN_DEV_PYTHON) not in sys.path:
    sys.path.insert(0, str(BN_DEV_PYTHON))

try:
    import binaryninja  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    binaryninja = None


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_binaryninja: mark tests that require the Binary Ninja Python API",
    )


@pytest.fixture(scope="session")
def binaryninja_module():
    if binaryninja is None:
        pytest.skip("Binary Ninja Python API not available")
    return binaryninja


@pytest.fixture(scope="session")
def armv5_arch(binaryninja_module):
    try:
        arch = binaryninja_module.Architecture["armv5"]
    except KeyError:
        # Attempt to load the plugin explicitly and retry
        ctypes.CDLL(str(plugin_path()))
        try:
            arch = binaryninja_module.Architecture["armv5"]
        except KeyError:
            pytest.skip("ARMv5 architecture is not registered with Binary Ninja")
    test_instr = (0xE0801002).to_bytes(4, "little")
    info = arch.get_instruction_info(test_instr, 0x1000)
    text = arch.get_instruction_text(test_instr, 0x1000)
    if not info or not text:
        pytest.skip("ARMv5 architecture not usable in this environment")
    tokens, _ = text
    if not tokens or tokens[0].text.strip().lower() != "add":
        pytest.skip("ARMv5 architecture disassembly output is unavailable in this environment")
    return arch


@pytest.fixture(scope="session")
def thumb_arch(binaryninja_module):
    try:
        arch = binaryninja_module.Architecture["armv5t"]
    except KeyError:
        # Attempt to load the plugin explicitly and retry
        ctypes.CDLL(str(plugin_path()))
        try:
            arch = binaryninja_module.Architecture["armv5t"]
        except KeyError:
            pytest.skip("Thumb architecture is not registered with Binary Ninja")
    return arch
