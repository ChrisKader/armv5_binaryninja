# arch_armv5 - ARMv5 Architecture Module

This directory contains the core Binary Ninja architecture plugin implementation.

## Structure

```
arch_armv5/
├── arch_armv5.cpp/h      # Architecture plugin interface
├── firmware/
│   ├── firmware_view.cpp/h   # Firmware BinaryViewType + registration
│   ├── firmware_scans.cpp    # Firmware scan passes
│   ├── firmware_vectors.cpp  # Vector table detection/resolution
│   ├── firmware_mmu.cpp      # MMU configuration analysis
│   ├── firmware_settings.cpp/h # Firmware settings + key registry
│   └── firmware_internal.h   # Shared firmware helpers
├── relocations/
│   └── relocations.cpp/h     # ELF relocation handling
├── il/
│   └── il.cpp/h              # LLIL lifting for ARM mode
├── armv5_disasm/         # ARM instruction decoder (pure C)
│   ├── armv5.c/h         # Decoder implementation
│   ├── test.c            # Standalone test harness
│   └── test.py           # Python disassembly tests
└── thumb_disasm/         # Thumb instruction decoder
    ├── arch_thumb.cpp    # Thumb architecture integration
    ├── il_thumb.cpp      # Thumb IL lifting
    ├── disassembler.cpp/h # Generated disassembler
    ├── spec.cpp/txt      # Instruction specifications
    └── generator.py      # Code generator from spec
```

## Key Classes

| Class | Description |
|-------|-------------|
| `ArmCommonArchitecture` | Base class with shared ARM/Thumb functionality |
| `Armv5Architecture` | 32-bit ARM mode (architecture name: `armv5`) |
| `ThumbArchitecture` | 16-bit Thumb mode (architecture name: `armv5t`) |
| `Armv5FirmwareView` | Custom BinaryViewType for bare-metal firmware |

## Supported Instructions

### Data Processing
AND, EOR, SUB, RSB, ADD, ADC, SBC, RSC, TST, TEQ, CMP, CMN, ORR, MOV, BIC, MVN

### Multiply
MUL, MLA, UMULL, UMLAL, SMULL, SMLAL

### DSP Multiply
SMULBB/BT/TB/TT, SMULWB/WT, SMLABB/BT/TB/TT, SMLAWB/WT, SMLALBB/BT/TB/TT

### Saturating Arithmetic
QADD, QSUB, QDADD, QDSUB

### Branch
B, BL, BX, BLX

### Load/Store
LDR, LDRB, LDRH, LDRSB, LDRSH, LDRD, STR, STRB, STRH, STRD

### Load/Store Multiple
LDM*, STM*, PUSH, POP

### VFPv2
VMOV, VADD, VSUB, VMUL, VDIV, VNEG, VABS, VSQRT, VCMP, VCVT, VLDR, VSTR, VLDM, VSTM, VPUSH, VPOP, VMRS, VMSR

### System
SWI/SVC, BKPT, MRS, MSR, CDP, LDC, STC, MCR, MRC, MCRR, MRRC, CLZ, SWP, SWPB, PLD

## Calling Conventions

| Convention | Description |
|------------|-------------|
| `aapcs` | ARM EABI (default) - r0-r3 args, r0 return |
| `cdecl` | Compatibility alias for AAPCS |
| `apcs` | Legacy ATPCS - 4-byte stack alignment |
| `irq-handler` | For interrupt handlers - all GPRs caller-saved |
| `task-entry` | RTOS task entry - r0/r1 as argc/argv |
| `linux-syscall` | Linux syscall - r7=syscall#, r0-r6 args |

## Firmware View Features

The `Armv5FirmwareView` provides automatic analysis for bare-metal binaries:

- Vector table detection (LDR PC or B instruction patterns)
- Exception handler function creation
- IRQ/FIQ return handler detection
- MMIO region identification
- Jump table detection
- Literal pool typing

## Building & Testing

See the [project README](../README.md) for build instructions.

```bash
# Quick disassembler test
./.build/test_armv5 e59ff018

# Disassembly verification
cd armv5_disasm && python3 test.py
```
