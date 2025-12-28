# Thumb Disassembler

16-bit Thumb instruction decoder for ARMv4T/ARMv5T (original Thumb only, not Thumb-2).

## Architecture

The disassembler uses a specification-driven approach:

1. **spec.txt** - Instruction encodings copied from ARM Architecture Reference Manual
2. **generator.py** - Parses spec.txt and generates C++ source
3. **spec.cpp** - Generated decoder tables and logic
4. **disassembler.cpp/h** - Interface for decomposition and string formatting

### Design Philosophy

Instruction tables form a graph where:
- Nodes are decode tables
- Edges connect tables that reference each other
- Terminal nodes contain instruction encodings

Decoding traverses from root to terminal, extracting fields along the way.

## Files

| File | Description |
|------|-------------|
| `arch_thumb.cpp` | Binary Ninja architecture integration |
| `il_thumb.cpp` | LLIL lifting for Thumb instructions |
| `disassembler.cpp/h` | Decomposer and string formatter |
| `spec.cpp` | Generated decode tables |
| `spec.txt` | Instruction specification source |
| `generator.py` | Code generator |

## Regenerating

If you modify `spec.txt`, regenerate the decoder:

```bash
python3 generator.py
```

This reads `spec.txt` and writes `spec.cpp`.

## Terminology

- **Decomposer**: Analyzes instruction bytes and produces an `InstructionInfo` struct with operation, registers, immediates, etc.
- **Disassembler**: Converts `InstructionInfo` to human-readable assembly text.

## Condition Codes

Thumb conditional branches use the same condition codes as ARM:

| Code | Meaning | Flags |
|------|---------|-------|
| EQ | Equal | Z=1 |
| NE | Not equal | Z=0 |
| CS/HS | Carry set / Unsigned >= | C=1 |
| CC/LO | Carry clear / Unsigned < | C=0 |
| MI | Negative | N=1 |
| PL | Positive or zero | N=0 |
| VS | Overflow | V=1 |
| VC | No overflow | V=0 |
| HI | Unsigned > | C=1 and Z=0 |
| LS | Unsigned <= | C=0 or Z=1 |
| GE | Signed >= | N=V |
| LT | Signed < | N!=V |
| GT | Signed > | Z=0 and N=V |
| LE | Signed <= | Z=1 or N!=V |

## Notes

- The `S` suffix indicates flag-updating instructions
- CMP, CMN, TST, TEQ implicitly update flags (no `S` suffix needed)
- Flags: N (negative), Z (zero), C (carry), V (overflow)
