# ARM926EJ-S MMU Configuration Analysis

This document describes the MMU (Memory Management Unit) configuration found in the ARMv5 firmware at `btrom.bin`.

## Overview

The firmware uses the ARM926EJ-S MMU with a single-level translation table (section descriptors only, no page tables). The translation table is located at physical address `0xA4034000`, which is an uncached alias of virtual address `0x00034000`.

## Physical Address Aliasing

This SoC uses physical address aliasing:
- `0xA4000000-0xA4FFFFFF` → `0x00000000-0x00FFFFFF` (uncached view)

When the MMU code writes TTBR = 0xA4034000, the translation table is actually at file offset 0x34000 in the ROM image.

## TTBR Detection

The TTBR (Translation Table Base Register) is set by:
```
MCR p15, 0, r0, c2, c0, 0   ; at offset 0xbe40
```

The value loaded into r0 comes from a PC-relative LDR at offset 0xbd68:
```
LDR r0, [PC, #0x124]        ; loads from literal pool at 0xbe94
```

Literal pool value at 0xbe94: `0xA4034000`

## MMU Setup Code Flow

The MMU initialization at `0xbcf0` follows this pattern:

### Phase 1: Default Fill (All 4GB)

```
r0 = 0xA4034000             ; translation table base
r1 = 0x32                   ; descriptor template
r4 = 0x100000               ; 1MB section size

loop:
    r2 = r1                 ; descriptor = base | template
    bl write_entry          ; store at table[(r1>>20)]
    r1 += r4                ; next section base
    cmp r1, r3              ; wraps around after 4096 iterations
    bne loop
```

This fills **all 4096 sections** (entire 4GB address space) with descriptor `0xXXX00032` where XXX is the section number.

### Default Descriptor: 0x00000032

| Bits | Field | Value | Meaning |
|------|-------|-------|---------|
| [1:0] | Type | 2 | Section descriptor |
| [2] | B | 0 | Not bufferable |
| [3] | C | 0 | Not cacheable |
| [4] | XN | 1 | Execute-Never |
| [5] | Domain[0] | 1 | Domain 1 |
| [11:10] | AP | 0 | No access |

**Effect**: Entire memory is marked as device memory, non-executable, no access.

### Phase 2: Override Specific Regions

Subsequent loops load configuration from tables in RAM and override specific sections with different attributes.

#### Descriptor Templates Found

| Value | Memory Type | XN | AP | Usage |
|-------|------------|----|----|-------|
| 0x00000032 | Strongly-ordered | 1 | 0 | Default (deny all) |
| 0x00000202 | Strongly-ordered | 0 | 0 | Executable but no access? |
| 0x00000c12 | Strongly-ordered | 1 | 3 | MMIO (full access, no execute) |

## Memory Map (Inferred)

Based on the code analysis:

| Range | Size | Type | Description |
|-------|------|------|-------------|
| 0x00000000-0x000FFFFF | 1MB | ROM | Code, executable, cached |
| 0x00100000-0x003FFFFF | 3MB | Internal SRAM | Data, cached |
| 0x40000000-0x4FFFFFFF | 256MB | Peripherals | MMIO, device memory |
| 0x80000000-0x8FFFFFFF | 256MB | External RAM | SDRAM, cached |
| 0xA4000000-0xA4FFFFFF | 16MB | Uncached alias | Physical view of 0x00xxxxxx |

## Translation Table Location

- **Physical Address**: 0xA4034000
- **Virtual Address**: 0x00034000
- **File Offset**: 0x34000
- **Size**: 16KB (4096 × 4-byte entries)

Note: The translation table is uninitialized in the ROM (all entries contain 0x0FF59FF0). It gets populated at runtime by the initialization code.

## Write Descriptor Function

Located at 0xbe78:
```
write_entry:
    push {r4}
    mov r4, r1, lsr #20     ; section index = VA >> 20
    mov r4, r4, lsl #2      ; offset = index * 4
    add r4, r0, r4          ; addr = table_base + offset
    str r2, [r4]            ; table[index] = descriptor
    pop {r4}
    bx lr
```

## Descriptor Types and Sizes

The ARM MMU supports different descriptor types at the first level:

| Bits [1:0] | Type | Size/Behavior |
|------------|------|---------------|
| 00 | Fault | No mapping (access generates abort) |
| 01 | Coarse Page Table | Points to 256-entry L2 table for 4KB pages |
| 10 | Section | Direct 1MB mapping |
| 11 | Fine Page Table | Points to 1024-entry L2 table for 1KB pages |

**In this firmware**: All configured entries use Section descriptors (type 2, 1MB each). The runtime code does not create any page tables, so the minimum mappable unit is 1MB.

The uninitialized table value `0x0FF59FF0` has bits [1:0] = 0 (Fault), meaning all accesses would abort until the initialization code runs.

## ARM Section Descriptor Format (Type 2)

```
31                    20 19 18 17 16 15 14  12 11 10 9  8   5 4 3 2 1 0
+------------------------+--+--+--+--+---+-----+-----+-+-----+-+-+-+---+
| Section Base Address   |NS| 0|nG| S|APX| TEX |  AP |P|Domain|XN|C|B| 1 0|
+------------------------+--+--+--+--+---+-----+-----+-+-----+-+-+-+---+
```

### Memory Type Encoding (TEX, C, B)

| TEX | C | B | Memory Type |
|-----|---|---|-------------|
| 000 | 0 | 0 | Strongly-ordered |
| 000 | 0 | 1 | Shareable Device |
| 000 | 1 | 0 | Write-through, no write-allocate |
| 000 | 1 | 1 | Write-back, no write-allocate |
| 001 | 0 | 0 | Non-cacheable |
| 010 | 0 | 0 | Non-shareable Device |

### Access Permission (APX, AP)

| APX | AP | Privileged | User |
|-----|-----|------------|------|
| 0 | 00 | No access | No access |
| 0 | 01 | Read/Write | No access |
| 0 | 10 | Read/Write | Read-only |
| 0 | 11 | Read/Write | Read/Write |
| 1 | 01 | Read-only | No access |
| 1 | 10 | Read-only | Read-only |
| 1 | 11 | Read-only | Read-only |

## Virtual Memory
- The ARM926EJ-S MMU is used to map NOR, SDRAM and peripherals in memory.
- Virtual memory is split into 1MB sections.
- The Translation Table Base Register (CP15 register c2) contains the address of an array of 4096 words, each one describes a section.
- The MMU allows both reads and writes on all mentioned sections, the others will trigger an exception for any access.

- 0x00000000-0x000FFFFF (1MB) - Internal RAM
- 0x10000000-0x11EFFFFF (31MB) - SDRAM
- 0x11F00000-0x11FFFFFF (1MB) - SDRAM
- 0x12000000-0x17FFFFFF (96MB)
- 0x18000000-0x180FFFFF (1MB) - alias of SDRAM
- 0x8FF00000-0x901FFFFF (3MB) - Memory-mapped I/O ports
- 0xA0000000-0xA00FFFFF (1MB)
- 0xA4000000-0xA40FFFFF (1MB) - alias of Internal RAM
- 0xA9000000-0xA90FFFFF (1MB)
- 0xAC000000-0xAC0FFFFF (1MB) - Memory-mapped I/O ports
- 0xB0000000-0xB00FFFFF (1MB) - Memory-mapped I/O ports
- 0xB4000000-0xB40FFFFF (1MB) - Memory-mapped I/O ports
- 0xB8000000-0xB80FFFFF (1MB) - Memory-mapped I/O ports
- 0xBC000000-0xBC0FFFFF (1MB) - Memory-mapped I/O ports
- 0xC0000000-0xC00FFFFF (1MB) - Memory-mapped I/O ports
- 0xC4000000-0xC40FFFFF (1MB) - Memory-mapped I/O ports
- 0xC8000000-0xC80FFFFF (1MB)
- 0xCC000000-0xCC0FFFFF (1MB) - Memory-mapped I/O ports
- 0xDC000000-0xDC0FFFFF (1MB) - Memory-mapped I/O ports

# 0x00000000-0x000FFFFF (1MB) - Internal RAM
  - 80KB of RAM, the last 16KB of which is repeated 4 times for a total address space of 128KB. This 128KB is repeated 8 times.
  - Physical address : 0xA4000000-0xA40FFFFF
  - not cached, not buffered
# 0x10000000-0x11EFFFFF (31MB) - SDRAM (First 31MB of RAM)
  - Physical address : 0x10000000-0x11EFFFFF
  - write-back cache
# 0x11F00000-0x11FFFFFF (1MB) - SDRAM (Last 1MB of RAM)
  - Physical address : 0x11F00000-0x11FFFFFF
  - not cached, not buffered
# 0x12000000-0x17FFFFFF (96MB) - Unknown
  - Physical address : 0x12000000-0x17FFFFFF
  - not cached, not buffered
# 0x18000000-0x180FFFFF (1MB) - alias of SDRAM
  - Physical address : 0x11E00000-0x11EFFFFF (alias of 0x11E00000-0x11EFFFFF virtual address)
  - write-back cache
# 0x8FF00000-0x901FFFFF (3MB) - Memory-mapped I/O ports
  - Physical address : 0x8FF000000-0x901FFFFF
  - not cached, not buffered
# 0xA0000000-0xA00FFFFF (1MB) - I/O ?
  - Physical address : 0xA0000000-0xA00FFFFF
  - not cached, not buffered
# 0xA4000000-0xA40FFFFF (1MB) - alias of Internal RAM
  - Physical address : 0xA4000000-0xA40FFFFF (alias of 0x00000000-0x000FFFFF virtual address)
  - not cached, not buffered
# 0xA9000000-0xA90FFFFF (1MB) - I/O ?
  - Physical address : 0xA9000000-0xA90FFFFF
  - not cached, not buffered
# 0xAC000000-0xAC0FFFFF (1MB) - Memory-mapped I/O ports
  - Physical address : 0xAC000000-0xAC0FFFFF
  - not cached, not buffered
# 0xB0000000-0xB00FFFFF (1MB) - Memory-mapped I/O ports
  - Physical address : 0xB0000000-0xB00FFFFF
  - not cached, not buffered
# 0xB4000000-0xB40FFFFF (1MB) - Memory-mapped I/O ports
  - Physical address : 0xB4000000-0xB40FFFFF
  - not cached, not buffered
# 0xB8000000-0xB80FFFFF (1MB) - Memory-mapped I/O ports
  - Physical address : 0xB8000000-0xB80FFFFF
  - not cached, not buffered
# 0xBC000000-0xBC0FFFFF (1MB) - Memory-mapped I/O ports
  - Physical address : 0xBC000000-0xBC0FFFFF
  - not cached, not buffered
# 0xC0000000-0xC00FFFFF (1MB) - Memory-mapped I/O ports
  - Physical address : 0xC0000000-0xC00FFFFF
  - not cached, not buffered
# 0xC4000000-0xC40FFFFF (1MB) - Memory-mapped I/O ports
  - Physical address : 0xC4000000-0xC40FFFFF
  - not cached, not buffered
# 0xC8000000-0xC80FFFFF (1MB) - I/O ?
  - Physical address : 0xC8000000-0xC80FFFFF
  - not cached, not buffered
# 0xCC000000-0xCC0FFFFF (1MB) - Memory-mapped I/O ports
  - Physical address : 0xCC000000-0xCC0FFFFF
  - not cached, not buffered
# 0xDC000000-0xDC0FFFFF (1MB) - Memory-mapped I/O ports
  - Physical address : 0xDC000000-0xDC0FFFFF
  - not cached, not buffered

# Memory-Mapped I/O
00000000 - Boot1 ROM
128kB of on-chip ROM.

10000000 - SDRAM
64 MiB, managed by 0x90120000.

90000000 - General Purpose I/O (GPIO)
See GPIO Pins

90010000 - Fast timer
The same interface as 900C0000/900D0000, see Second timer.

90020000 - Serial UART
PL011.

90030000 - Fastboot RAM
4KiB of RAM, not cleared on resets/reboots.

Only the lower 12 bits of the address are used, so the content aliases at 0x1000 and so on.

The OS uses that to store some data which is used during boot to restore the previous state of the device.

The installer images use the area at 0x200 to store some variables for tracking the progress.

90040000 - SPI controller
FTSSP010 SPI controller connected to the LCD.

90050000 - I2C controller
The Touchpad on the CX II is accessed through this controller. See Keypads#Touchpad I²C for protocol details. It seems to be a Synopsys Designware I2C adapter.

90050000 (R/W): Control register?
90050004 (?): ?
90050010 (R/W): Data/command register
90050014 (R/W): Speed divider for high period (standard speed) OS: 0x9c
90050018 (R/W): Speed divider for low period (standard speed) OS: 0xea
9005001c (R/W): Speed divider for high period (high speed) OS: 0x3b
90050020 (R/W): Speed divider for low period (high speed) OS: 0x2b
9005002c (R/W?): Interrupt status
90050030 (R/W): Interrupt mask
90050040 (R/W): Interrupt clear. Write 1 bits to clear
9005006c (R/W): Enable register
90050070 (R): Status register
90050074 (R?/W): TX FIFO?
90050078 (R?/W): RX FIFO?
900500f4 (?): ?
90050080 (?): ?
90060000 - Watchdog timer
Possibly an ARM SP805 or compatible. Runs at the APB clock frequency.

90070000 - Second Serial UART
PL011.

90080000 - Cradle SPI Controller
An FTSSP010 for communicating with the EEPROM in the cradle.

90090000 - Real-Time Clock (RTC)
Similar to the ARM PrimeCell PL031, but interrupt registers are different.

90090000 (R): Current time, increments by 1 every second.
90090004 (R/W): Alarm value. When the time passes this, interrupt becomes active.
90090008 (R/W): Sets the value of 90090000 (clock will not read new time until a couple seconds later). Reads last value written.
9009000C (R/W): Interrupt mask (1-bit)
90090010 (R/W): Masked interrupt status, reads 1 if interrupt active and mask bit is set. Write 1 to acknowledge.
90090014 (R): Status
Bit 0: Time setting in progress
Bit 1: Alarm setting in progress
Bit 2: Interrupt acknowledgment in progress
Bit 3: Interrupt mask setting in progress
900A0000 - Miscellaneous
Seems to be similar to CX and Classic, except for the model ID at 900A0000 which is now 0x202.

900B0000 - ADC
A Faraday FTADCC010.

900C0000 - First timer
Same port structure as Second timer.

900D0000 - Second timer
Timer is a SP804.

900E0000 - Keypad controller
See also Keypads for information about the keypads themselves.

900E0000 (R/W):
Bits 0-1: Scan mode
Mode 0: Idle.
Mode 1: Indiscriminate key detection. Data registers are not updated, but whenever any key is pressed, interrupt bit 2 is set (and cannot be cleared until the key is released).
Mode 2: Single scan. The keypad is scanned once, and then the mode returns to 0.
Mode 3: Continuous scan. When scanning completes, it just starts over again after a delay.
Bits 2-15: Number of APB cycles to wait before scanning each row
Bits 16-31: Number of APB cycles to wait between scans
900E0004 (R/W):
Bits 0-7: Number of rows to read (later rows are not updated in 900E0010-900E002F, and just read as whatever they were before being disabled)
Bits 8-15: Number of columns to read (later column bits in a row are set to 1 when it is updated)
900E0008 (R/W): Keypad interrupt status/acknowledge (3-bit). Write "1" bits to acknowledge.
Bit 0: Keypad scan complete
Bit 1: Keypad data register changed
Bit 2: Key pressed in mode 1
900E000C (R/W): Keypad interrupt mask (3-bit). Set each bit to 1 if the corresponding event in [900E0008] should cause an interrupt.
900E0010-900E002F (R): Keypad data, one halfword per row.
900E0030-900E003F (R/W): Keypad GPIOs. Each register is 20 bits, with one bit per GPIO. The role of each register is unknown.
900E0040 (R/W): Interrupt enable. Bits unknown but seems to be related to touchpad. Causes interrupt on touchpad touched.
900E0044 (R/W): Interrupt status. Bits unknown. Write 1s to acknowledge.
900E0048 (R/W): Unknown
90120000 - SDRAM Controller
An FTDDR3030.

90130000 - Unknown Controller for the LCD Backlight
The OS enables the LCD backlight by writing 255 to 90130018. The brightness is controlled by 90130014, the OS writes 0 (brightest) to 225 (darkest).

90140000 - Power management
A new "Aladdin PMU" unit. Not much known.

90140000 (R/?): Reason for waking up from low-power mode.
90140050 (R/W): Disable bus access to peripherals. Reads will just return the last word read from anywhere in the address range, and writes will be ignored.
Bit 9: #C8010000 - Triple DES encryption
Bit 10: #CC000000 - SHA-256 hash generator
Bit 13: #90060000 - Watchdog timer (?)
Bit 26: #90050000 - I2C controller (?)
A0000000 - Boot1 ROM again
Mirror of the ROM at 0.

A4000000 - Internal SRAM
0x40000 bytes SRAM, managed by the controller at ?.

A8000000 - Magic VRAM
0x25800 bytes SRAM for an LCD framebuffer.

It is wired up in a way that the written data is X-Y swapped and rotated, so that writing a 320x240 image with (0/0) at the top left results in a 320x320 image in the right orientation for the LCD. This means that it can't be used as generic RAM. How this mechanism works isn't known yet.

B0000000 - USB OTG/Host/Device controller (top)
An FOTG210 connected to the top USB port.

B4000000 - USB OTG/Host/Device controller (bottom)
An FOTG210 connected to the bottom USB port (dock connector).

B8000000 - SPI NAND controller
An FTSPI020 with a MICRON 1Gb flash at CS 1.

BC000000 - DMA controller
An FTDMAC020 with main SDRAM and LCD RAM (everything?) connected to AHB1. The OS uses this to copy the framebuffer into LCD RAM. It is a derivative of the PL080 with some changes

C0000000 - LCD controller
A PL111.

C8010000 - Triple DES encryption
Implements the Triple DES encryption algorithm.

C8010000 (R/W): Right half of block
C8010004 (R/W): Left half of block. Writing this causes the block to be encrypted/decrypted.
C8010008 (R/W): Right 32 bits of key 1
C801000C (R/W):
Bits 0-23: Left 24 bits of key 1
Bit 30: Set to 0 to encrypt, 1 to decrypt
C8010010 (R/W): Right 32 bits of key 2
C8010014 (R/W): Left 24 bits of key 2
C8010018 (R/W): Right 32 bits of key 3
C801001C (R/W): Left 24 bits of key 3
CC000000 - SHA-256 hash generator
Implements the SHA-256 hash algorithm, which is used in cryptographic signatures.

CC000000 (R): Busy if bit 0 set
CC000000 (W): Write 0x10 and then 0x0 to initialize. Write 0xA to process first block, 0xE to process subsequent blocks
CC000008 (R/W): Some sort of bus write-allow register? If a bit is set, it allows R/W access to the registers of the peripheral, if clear, R/O access only. Don't know what it's doing here, but it's here anyway.
Bit 8: #CC000000 - SHA-256 hash generator
Bit 10: ?
CC000010-CC00004F (R/W): 512-bit block
CC000060-CC00007F (R): 256-bit state
DC000000 - Interrupt controller
See Interrupts. The controller is a PL190.