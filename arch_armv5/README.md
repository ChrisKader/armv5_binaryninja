# ARMv5 Architecture Plugin for Binary Ninja

This plugin adds support for ARMv5T/ARMv5TE/ARMv5TEJ processors to Binary Ninja.

## Features

### Supported Instruction Sets
- **ARMv5T**: Base 32-bit ARM instruction set with Thumb interworking
- **ARMv5TE**: Enhanced DSP instructions (SMUL, SMLA, saturating arithmetic)
- **Original Thumb**: 16-bit Thumb instruction set (NOT Thumb-2)
- **VFPv2**: Optional floating-point support (basic operations)

### Capabilities
- Full disassembly of ARM and Thumb instructions
- Intermediate Language (IL) lifting for analysis
- Condition code handling
- ARM/Thumb mode switching via BX/BLX
- Support for DSP multiply and saturating arithmetic intrinsics

### Supported Processors
This plugin is suitable for analyzing code from processors like:
- ARM926EJ-S
- ARM946E-S
- ARM966E-S
- ARM1026EJ-S
- Intel XScale
- And other ARMv5-compatible cores

## Building

### Prerequisites
- CMake 3.15 or later
- C++17 compatible compiler
- Binary Ninja and its API

### Build Steps

1. Clone the Binary Ninja API repository:
```bash
git clone https://github.com/Vector35/binaryninja-api.git
```

2. Build the plugin:
```bash
cd arch_armv5
mkdir build && cd build
cmake .. -DBN_API_PATH=/path/to/binaryninja-api -DBN_INSTALL_DIR=/path/to/binaryninja
make
```

3. Install the plugin:
```bash
make install
```

Or manually copy the built library to your Binary Ninja plugins directory:
- **macOS**: `~/Library/Application Support/Binary Ninja/plugins/`
- **Linux**: `~/.binaryninja/plugins/`
- **Windows**: `%APPDATA%\Binary Ninja\plugins\`

## Usage

After installation, Binary Ninja will automatically recognize the `armv5` and `thumb` architectures. You can:

1. Open a binary compiled for ARMv5
2. Manually set the architecture via `Edit > Set Architecture > armv5`
3. Use the Python API:
```python
bv.platform = Platform['linux-armv5']
```

### Architecture Names
- `armv5`: 32-bit ARM mode
- `thumb`: 16-bit Thumb mode

The plugin automatically handles ARM/Thumb mode switching based on:
- Branch target addresses (LSB indicates Thumb mode)
- BX/BLX instructions

## Differences from ARMv7

This plugin specifically targets ARMv5, which differs from ARMv7 in several ways:

### NOT Supported (ARMv6/ARMv7 features):
- Thumb-2 (32-bit Thumb instructions)
- NEON/Advanced SIMD
- VFPv3 and later floating-point extensions
- Memory barriers (DMB, DSB, ISB)
- IT blocks
- Many ARMv6+ instructions (REV, SXTB, UXTB, etc.)

### Supported (ARMv5 specific):
- Original 16-bit Thumb
- DSP extensions (SMLAxy, SMULxy, QADD, QSUB, etc.)
- CLZ (Count Leading Zeros)
- VFPv2 basic operations
- Enhanced ARM/Thumb interworking

## Project Structure

```
arch_armv5/
├── CMakeLists.txt          # Build configuration
├── README.md               # This file
├── arch_armv5.h            # Architecture plugin header
├── arch_armv5.cpp          # Main plugin implementation
├── il.h                    # IL lifting header
├── il.cpp                  # IL lifting implementation
├── armv5_disasm/
│   ├── armv5.h             # ARM disassembler header
│   └── armv5.c             # ARM disassembler implementation
└── thumb_disasm/
    ├── thumb.h             # Thumb disassembler header
    └── thumb.c             # Thumb disassembler implementation
```

## Contributing

Contributions are welcome! Areas that could use improvement:
- Additional VFP instruction support
- Coprocessor instruction decoding
- Test suite
- Performance optimizations

## License

This project is provided under the same license as the Binary Ninja API.

## References

- [ARM Architecture Reference Manual (ARMv5)](https://developer.arm.com/documentation/ddi0100/i)
- [Binary Ninja API Documentation](https://api.binary.ninja/)
- [ARMv7 Architecture Plugin](https://github.com/Vector35/binaryninja-api/tree/dev/arch/armv7)
