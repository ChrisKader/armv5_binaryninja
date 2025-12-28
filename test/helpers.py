"""Shared testing helpers for the ARMv5 Binary Ninja plugin tests."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = PROJECT_ROOT / ".build"
PLUGIN_NAME = "libarch_armv5.dylib"


def plugin_path() -> Path:
    """Return the path to the compiled disassembler module."""
    path = BUILD_DIR / PLUGIN_NAME
    if not path.exists():
        pytest.skip(f"Plugin not built: expected {path}")
    return path


def parse_operands(operands_text: str) -> List[str]:
    """Parse operand text while respecting brackets and post-indexed syntax."""
    operands: List[str] = []
    current = []
    bracket_depth = 0
    brace_depth = 0
    post_indexed = False

    i = 0
    while i < len(operands_text):
        char = operands_text[i]

        if char == '[':
            bracket_depth += 1
            current.append(char)
        elif char == ']':
            bracket_depth -= 1
            current.append(char)
            if bracket_depth == 0 and operands_text[i + 1:i + 4] == ', #':
                post_indexed = True
        elif char == '{':
            brace_depth += 1
            current.append(char)
        elif char == '}':
            brace_depth -= 1
            current.append(char)
        elif char == ',' and bracket_depth == 0 and brace_depth == 0 and not post_indexed:
            operand = ''.join(current).strip()
            if operand:
                operands.append(operand)
            current = []
        else:
            current.append(char)
            if post_indexed and bracket_depth == 0 and char == ',':
                operand = ''.join(current[:-1]).strip()
                if operand:
                    operands.append(operand)
                current = [',']
                post_indexed = False
        i += 1

    operand = ''.join(current).strip()
    if operand:
        operands.append(operand)

    return operands


def assert_instruction_case(arch, case: Dict[str, object]) -> None:
    """Validate that an instruction decodes and formats as expected."""
    instruction_value = case['instruction']
    address = case.get('address', 0)
    expected_length = case.get('expected_info', {}).get('length', 4)

    instr_bytes = instruction_value.to_bytes(4, byteorder='little')
    info = arch.get_instruction_info(instr_bytes, address)
    assert info is not None, f"Instruction info not available for {case['name']}"
    assert info.length == expected_length, (
        f"Expected length {expected_length}, got {info.length} for {case['name']}"
    )

    text_tokens, length = arch.get_instruction_text(instr_bytes, address)
    assert length == expected_length, (
        f"Text length mismatch for {case['name']}: expected {expected_length}, got {length}"
    )
    instruction_text = ''.join(token.text for token in text_tokens).strip()
    parts = instruction_text.split(maxsplit=1)
    assert parts, f"No disassembly text for {case['name']}"

    actual_mnemonic = parts[0]
    expected_mnemonic = case['expected_mnemonic']
    assert actual_mnemonic == expected_mnemonic, (
        f"Expected mnemonic '{expected_mnemonic}', got '{actual_mnemonic}' in '{instruction_text}'"
    )

    expected_operands: Iterable[str] = case.get('expected_operands', [])
    if expected_operands:
        if len(parts) > 1:
            operands_text = parts[1]
            actual_operands = parse_operands(operands_text)
        else:
            actual_operands = []
        assert list(expected_operands) == actual_operands, (
            f"Operand mismatch for {case['name']}: expected {list(expected_operands)}, "
            f"got {actual_operands} in '{instruction_text}'"
        )
