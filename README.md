# ARMv5 Architecture Plugin for Binary Ninja

A Binary Ninja architecture plugin providing disassembly, instruction rendering, and IL lifting for ARMv5T/ARMv5TE/ARMv5TEJ processors.

## Features

- **ARM Mode**: Full 32-bit ARMv5 instruction set
- **Thumb Mode**: Original 16-bit Thumb (not Thumb-2)
- **VFPv2**: Basic floating-point operations
- **DSP Extensions**: SMUL, SMLA, saturating arithmetic
- **IL Lifting**: Complete LLIL support for analysis
- **Firmware Detection**: Automatic vector table parsing for bare-metal binaries

### Supported Processors

ARM926EJ-S, ARM946E-S, ARM966E-S, ARM1026EJ-S, Intel XScale, and other ARMv5-compatible cores.

## Building

### Prerequisites

- CMake 3.15+
- C++20 compatible compiler
- Binary Ninja (with API)

### Build Steps

```bash
# Clone with submodules
git clone --recursive <repo-url>
cd armv5_binaryninja

# Or initialize submodules if already cloned
git submodule update --init --recursive

# Build
make

# Install plugin (creates symlink)
make install
```

Build outputs are placed in `.build/`:
- `libarch_armv5.dylib` - Binary Ninja plugin
- `test_armv5` - Standalone disassembler test
- `libdisasm.dylib` - Shared library for Python tests

## Usage

After installation, Binary Ninja will recognize the `armv5` and `armv5t` architectures.

### Architecture Names

| Name | Description |
|------|-------------|
| `armv5` | 32-bit ARM mode |
| `armv5t` | 16-bit Thumb mode |

The plugin automatically handles ARM/Thumb mode switching based on branch targets.

### Python API

```python
import binaryninja as bn

# Load firmware with ARMv5 platform
bv = bn.load('firmware.bin', options={'loader.platform': 'armv5'})
```

## Testing

```bash
# Standalone disassembler test
./.build/test_armv5 e59ff018

# Python disassembly tests
cd arch_armv5/armv5_disasm
python3 test.py

# Full test suite (requires Binary Ninja Python)
BN_USER_DIRECTORY=~/.binaryninja-dev python3 -m pytest test/ -v
```

## Project Structure

```
armv5_binaryninja/
├── arch_armv5/           # Main plugin source
│   ├── arch_armv5.cpp    # Architecture plugin interface
│   ├── il.cpp            # LLIL lifting
│   ├── armv5_disasm/     # ARM instruction decoder (C)
│   └── thumb_disasm/     # Thumb decoder (spec-generated)
├── test/                 # Test suite
├── data/                 # Test binaries
├── binaryninja-api/      # Binary Ninja API (submodule)
└── docs/                 # Documentation
```

## License

This project is provided under the same license as the Binary Ninja API.

## References

- [ARM Architecture Reference Manual (ARMv5)](https://developer.arm.com/documentation/ddi0100/i)
- [Binary Ninja API Documentation](https://api.binary.ninja/)
