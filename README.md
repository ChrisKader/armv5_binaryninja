# ARMv5 Architecture Plugin for Binary Ninja

A Binary Ninja architecture plugin providing disassembly, instruction rendering, and IL lifting for ARMv5T/ARMv5TE/ARMv5TEJ processors.

## Features

- ARM Mode: ARMv5 core instruction set coverage (see INSTRUCTIONS.md for status)
- Thumb Mode: Original 16-bit Thumb (not Thumb-2)
- VFPv2: Basic floating-point operations
- DSP Extensions: SMUL, SMLA, saturating arithmetic
- IL Lifting: LLIL support for covered instructions
- Firmware Detection: Automatic vector table parsing for bare-metal binaries

### Supported Processors

Examples: ARM926EJ-S, ARM946E-S, ARM966E-S, ARM1026EJ-S, Intel XScale, and other ARMv5-compatible cores.

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
|-- arch_armv5/                        # Main plugin source
|   |-- arch_armv5.cpp/h               # Plugin registration and wiring
|   |-- arch/
|   |   |-- armv5_architecture.cpp/h   # ARM mode architecture implementation
|   |   `-- arm_common.cpp             # ArmCommonArchitecture methods
|   |-- conventions/
|   |   `-- calling_conventions.cpp/h  # Calling convention definitions/registration
|   |-- recognizers/
|   |   `-- function_recognizers.cpp/h # Function recognizers (ARM/Thumb thunks)
|   |-- platforms/
|   |   `-- platform_recognizers.cpp/h # ELF/raw platform detection
|   |-- firmware/                      # Firmware BinaryViewType
|   |   |-- firmware_view.cpp/h
|   |   |-- firmware_scans.cpp
|   |   |-- firmware_vectors.cpp
|   |   |-- firmware_mmu.cpp
|   |   |-- firmware_settings.cpp/h
|   |   `-- firmware_internal.h
|   |-- relocations/                   # Relocation handling
|   |   `-- relocations.cpp/h
|   |-- il/                            # LLIL lifting
|   |   `-- il.cpp/h
|   |-- armv5_disasm/                  # ARM instruction decoder (C)
|   `-- thumb_disasm/                  # Thumb decoder (spec-generated)
|-- test/                              # Test suite
|-- data/                              # Test binaries
|-- binaryninja-api/                   # Binary Ninja API (submodule)
`-- docs/                              # Documentation
```

## Architecture Module

### Key Classes

| Class | Description |
|-------|-------------|
| `ArmCommonArchitecture` | Base class with shared ARM/Thumb functionality |
| `Armv5Architecture` | 32-bit ARM mode (architecture name: `armv5`) |
| `ThumbArchitecture` | 16-bit Thumb mode (architecture name: `armv5t`) |
| `Armv5FirmwareView` | Custom BinaryViewType for bare-metal firmware |

### Calling Conventions

| Convention | Description |
|------------|-------------|
| `aapcs` | ARM EABI (default) - r0-r3 args, r0 return |
| `cdecl` | Compatibility alias for AAPCS |
| `apcs` | Legacy ATPCS - 4-byte stack alignment |
| `irq-handler` | For interrupt handlers - all GPRs caller-saved |
| `task-entry` | RTOS task entry - r0/r1 as argc/argv |
| `linux-syscall` | Linux syscall - r7=syscall#, r0-r6 args |

### Firmware View Features

The `Armv5FirmwareView` provides automatic analysis for bare-metal binaries:

- Vector table detection (LDR PC or B instruction patterns)
- Exception handler function creation
- IRQ/FIQ return handler detection
- MMIO region identification
- Jump table detection
- Literal pool typing

## Instruction Coverage and Lifting Status

See [INSTRUCTIONS.md](INSTRUCTIONS.md) for the full coverage matrix and tracking notes.

## License

This project is provided under the same license as the Binary Ninja API.

## References

- ARM Architecture Reference Manual (ARMv5), DDI 0100I
- Binary Ninja API Documentation
