# ARMv5 Instruction Disassembly/Lifting Completion Tracking

This document tracks the completion status of ARMv5 instruction support in this Binary Ninja architecture plugin.

Reference: [ARM Architecture Reference Manual (ARM ARM), DDI 0100I](https://developer.arm.com/documentation/ddi0100/i/)

## Status Legend

| Status | Description |
|--------|-------------|
| Full | Complete implementation |
| Partial | Incomplete implementation (some encodings or edge cases missing) |
| None | Not implemented |
| N/A | Not applicable to ARMv5 |

---

## ARM Mode (32-bit) Instructions

### Data Processing Instructions

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| adc | Full | Full | |
| add | Full | Full | |
| and | Full | Full | |
| bic | Full | Full | |
| cmn | Full | Full | |
| cmp | Full | Full | |
| eor | Full | Full | |
| mov | Full | Full | |
| mvn | Full | Full | |
| orr | Full | Full | |
| rsb | Full | Full | |
| rsc | Full | Full | |
| sbc | Full | Full | |
| sub | Full | Full | |
| teq | Full | Full | |
| tst | Full | Full | |

### Multiply Instructions

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| mul | Full | Full | |
| mla | Full | Full | |
| umull | Full | Full | |
| umlal | Full | Full | |
| smull | Full | Full | |
| smlal | Full | Full | |

### DSP Multiply Extensions (ARMv5TE)

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| smulbb | Full | Full | 16x16 signed multiply |
| smulbt | Full | Full | 16x16 signed multiply |
| smultb | Full | Full | 16x16 signed multiply |
| smultt | Full | Full | 16x16 signed multiply |
| smulwb | Full | Full | 32x16 signed multiply |
| smulwt | Full | Full | 32x16 signed multiply |
| smlabb | Full | Full | 16x16 + 32 signed MAC |
| smlabt | Full | Full | 16x16 + 32 signed MAC |
| smlatb | Full | Full | 16x16 + 32 signed MAC |
| smlatt | Full | Full | 16x16 + 32 signed MAC |
| smlawb | Full | Full | 32x16 + 32 signed MAC |
| smlawt | Full | Full | 32x16 + 32 signed MAC |
| smlalbb | Full | Full | 16x16 + 64 signed MAC |
| smlalbt | Full | Full | 16x16 + 64 signed MAC |
| smlaltb | Full | Full | 16x16 + 64 signed MAC |
| smlaltt | Full | Full | 16x16 + 64 signed MAC |

### Saturating Arithmetic (ARMv5TE)

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| qadd | Full | Full | Lifted as intrinsic |
| qsub | Full | Full | Lifted as intrinsic |
| qdadd | Full | Full | Lifted as intrinsic |
| qdsub | Full | Full | Lifted as intrinsic |

### Miscellaneous Arithmetic

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| clz | Full | Full | |

### Branch Instructions

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| b | Full | Full | |
| bl | Full | Full | |
| bx | Full | Full | |
| blx | Full | Full | Register and immediate forms |

### Load/Store Word and Unsigned Byte

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| ldr | Full | Full | All addressing modes |
| ldrb | Full | Full | |
| str | Full | Full | All addressing modes |
| strb | Full | Full | |

### Load/Store Halfword and Signed Byte

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| ldrh | Full | Full | |
| ldrsh | Full | Full | |
| ldrsb | Full | Full | |
| strh | Full | Full | |

### Load/Store Doubleword (ARMv5TE)

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| ldrd | Full | Full | |
| strd | Full | Full | |

### Load/Store Multiple

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| ldm | Full | Full | |
| ldmia | Full | Full | |
| ldmib | Full | Full | |
| ldmda | Full | Full | |
| ldmdb | Full | Full | |
| stm | Full | Full | |
| stmia | Full | Full | |
| stmib | Full | Full | |
| stmda | Full | Full | |
| stmdb | Full | Full | |
| push | Full | Full | Alias for STMDB SP!, {reglist} |
| pop | Full | Full | Alias for LDMIA SP!, {reglist} |

### Semaphore Instructions

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| swp | Full | Full | Deprecated in ARMv6+ |
| swpb | Full | Full | Deprecated in ARMv6+ |

### Exception-Generating Instructions

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| swi | Full | Full | Lifted as syscall |
| svc | Full | Full | Alias for SWI |
| bkpt | Full | Full | Lifted as breakpoint |

### Status Register Access

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| mrs | Full | Full | Lifted as intrinsic |
| msr | Full | Full | Lifted as intrinsic |

### Coprocessor Instructions

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| cdp | Full | Full | Lifted as intrinsic |
| ldc | Full | Full | Lifted as intrinsic |
| stc | Full | Full | Lifted as intrinsic |
| mcr | Full | Full | Lifted as intrinsic |
| mrc | Full | Full | Lifted as intrinsic |
| mcrr | Full | Full | Lifted as intrinsic |
| mrrc | Full | Full | Lifted as intrinsic |

### Preload (ARMv5TE)

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| pld | Full | Full | Lifted as intrinsic (hint) |

### Pseudo-operations

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| nop | Full | Full | MOV R0, R0 |
| udf | Full | Full | Undefined instruction trap |

---

## VFPv2 Instructions (Optional Coprocessor)

### VFP Data Processing

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| vadd | Full | Full | F32/F64 |
| vsub | Full | Full | F32/F64 |
| vmul | Full | Full | F32/F64 |
| vnmul | Full | Full | F32/F64 |
| vmla | Full | Full | F32/F64 |
| vmls | Full | Full | F32/F64 |
| vdiv | Full | Full | F32/F64 |
| vneg | Full | Full | F32/F64 |
| vabs | Full | Full | F32/F64 |
| vsqrt | Full | Full | F32/F64 |
| vcmp | Full | Full | F32/F64 |
| vcmpe | Full | Full | F32/F64, with exception |
| vcvt | Full | Full | Various conversions |

### VFP Load/Store

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| vldr | Full | Full | F32/F64 |
| vstr | Full | Full | F32/F64 |
| vldm | Full | Full | F32/F64 |
| vstm | Full | Full | F32/F64 |
| vpush | Full | Full | F32/F64 |
| vpop | Full | Full | F32/F64 |

### VFP Register Transfer

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| vmov | Full | Full | Various forms |
| vmrs | Full | Full | Copy FPSCR to ARM register |
| vmsr | Full | Full | Copy ARM register to FPSCR |
| fmstat | Full | Full | Copy VFP flags to APSR |

---

## Thumb Mode (16-bit) Instructions

### Data Processing

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| adc | Full | Full | |
| add | Full | Full | |
| and | Full | Full | |
| asr | Full | Full | |
| bic | Full | Full | |
| cmn | Full | Full | |
| cmp | Full | Full | |
| eor | Full | Full | |
| lsl | Full | Full | |
| lsr | Full | Full | |
| mov | Full | Full | |
| mul | Full | Full | |
| mvn | Full | Full | |
| orr | Full | Full | |
| ror | Full | Full | |
| rsb | Full | Full | |
| sbc | Full | Full | |
| sub | Full | Full | |
| tst | Full | Full | |
| teq | Full | Full | |

### Branch Instructions

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| b | Full | Full | Conditional and unconditional |
| bl | Full | Full | |
| blx | Full | Full | |
| bx | Full | Full | |

### Load/Store

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| ldr | Full | Full | All Thumb addressing modes |
| ldrb | Full | Full | |
| ldrh | Full | Full | |
| ldrsb | Full | Full | |
| ldrsh | Full | Full | |
| str | Full | Full | |
| strb | Full | Full | |
| strh | Full | Full | |

### Load/Store Multiple

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| ldmia | Full | Full | |
| stmia | Full | Full | |
| push | Full | Full | |
| pop | Full | Full | |

### Miscellaneous

| Mnem | Disasm | Lifting | Notes |
|------|--------|---------|-------|
| adr | Full | Full | |
| bkpt | Full | Full | |
| clz | Full | Full | |
| nop | Full | Full | |
| svc | Full | Full | |
| udf | Full | Full | |

---

## Summary

| Category | Total | Full Disasm | Full Lifting |
|----------|-------|-------------|--------------|
| ARM Data Processing | 16 | 16 | 16 |
| ARM Multiply | 6 | 6 | 6 |
| ARM DSP Multiply | 16 | 16 | 16 |
| ARM Saturating | 4 | 4 | 4 |
| ARM Misc Arithmetic | 1 | 1 | 1 |
| ARM Branch | 4 | 4 | 4 |
| ARM Load/Store | 14 | 14 | 14 |
| ARM Load/Store Multiple | 12 | 12 | 12 |
| ARM Semaphore | 2 | 2 | 2 |
| ARM Exception | 3 | 3 | 3 |
| ARM Status Register | 2 | 2 | 2 |
| ARM Coprocessor | 7 | 7 | 7 |
| ARM Preload | 1 | 1 | 1 |
| ARM Pseudo-ops | 2 | 2 | 2 |
| VFP Data Processing | 13 | 13 | 13 |
| VFP Load/Store | 6 | 6 | 6 |
| VFP Register Transfer | 4 | 4 | 4 |
| Thumb (all) | ~40 | ~40 | ~40 |
| **Total** | **~153** | **~153** | **~153** |

All ARMv5 instructions are now fully supported with complete disassembly and IL lifting.

---

## Contributing

When adding instruction support:

1. Add disassembly in `arch_armv5/armv5_disasm/armv5.c` (ARM) or `arch_armv5/thumb_disasm/` (Thumb)
2. Add IL lifting in `arch_armv5/il/il.cpp` (ARM) or `arch_armv5/thumb_disasm/il_thumb.cpp` (Thumb)
3. Add tests in `test/` directory
4. Update this document

Please report any discrepancies between this document and actual behavior as issues.
