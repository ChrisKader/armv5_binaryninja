## Determining the image base from an ARM vector table (with built-in validation)

Our goal is to compute the image base (the address the binary expects to be loaded at) using only the ARM exception vector table at the start of the file, and to validate the result by verifying that derived offsets land on plausible code inside the binary.

### Binary size

- Length: 643,568 bytes (`0x9D1F0`)

---

## 1) Vector table mechanism (classic ARM vectors)

At file offsets `0x00` through `0x1C`, there are 8 identical ARM instructions forming a vector-table stub:

- `0xE59FF018` -> `LDR pc, [pc, #0x18]`

In ARM state, the PC value observed by the instruction is `X + 8` (where `X` is the instruction address). Therefore, the effective address loaded from is:

- `(X + 8) + 0x18 = X + 0x20`

So each vector entry at `X` loads a 32-bit word located exactly `0x20` bytes ahead of that instruction:

- Instruction at `X` loads the word at `X + 0x20`

Those 32-bit words are typically absolute runtime addresses of the exception handlers.

---

## Vector table instructions (file offsets `0x00..0x1C`)

All table columns are centered. The last column shows the raw instruction bytes as they appear in the file (little-endian).

| Instr @ | Word | Disasm | Raw hex |
|:------:|:----:|:------:|:-------:|
| `0x00` | `0xE59FF018` | `LDR pc, [pc, #0x18]` | `18 F0 9F E5` |
| `0x04` | `0xE59FF018` | `LDR pc, [pc, #0x18]` | `18 F0 9F E5` |
| `0x08` | `0xE59FF018` | `LDR pc, [pc, #0x18]` | `18 F0 9F E5` |
| `0x0C` | `0xE59FF018` | `LDR pc, [pc, #0x18]` | `18 F0 9F E5` |
| `0x10` | `0xE59FF018` | `LDR pc, [pc, #0x18]` | `18 F0 9F E5` |
| `0x14` | `0xE59FF018` | `LDR pc, [pc, #0x18]` | `18 F0 9F E5` |
| `0x18` | `0xE59FF018` | `LDR pc, [pc, #0x18]` | `18 F0 9F E5` |
| `0x1C` | `0xE59FF018` | `LDR pc, [pc, #0x18]` | `18 F0 9F E5` |

---

## Vector table literals (file offsets `0x20..0x3C`)

All table columns are centered. The last column shows the raw literal bytes as they appear in the file (little-endian).

| Lit @ | Word | Vector | Raw hex |
|:----:|:----:|:------:|:-------:|
| `0x20` | `0x11217480` | `reset` | `80 74 21 11` |
| `0x24` | `0x11217B20` | `undef` | `20 7B 21 11` |
| `0x28` | `0x11217B5C` | `swi` | `5C 7B 21 11` |
| `0x2C` | `0x11217B98` | `prefetch_abort` | `98 7B 21 11` |
| `0x30` | `0x11217BD4` | `data_abort` | `D4 7B 21 11` |
| `0x34` | `0x11217CAC` | `reserved` | `AC 7C 21 11` |
| `0x38` | `0x00000040` | `irq` | `40 00 00 00` |
| `0x3C` | `0x112177AC` | `fiq` | `AC 77 21 11` |

Most literals fall in the same region (`0x112xxxxx`), strongly suggesting they are pointers into a single loaded image.

---

## Hex view (like the binary itself, with highlighted words)

GitHub sanitizes CSS, so this uses colored square emojis as the "highlight" markers.

The bytes shown are the raw bytes as stored in the file (little-endian). The word in parentheses is the decoded 32-bit value.

|      |`00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F`|
|:----:|:-----------------------------------------------:|
|`0x00`|`E5 9F F0 18 E5 9F F0 18 E5 9F F0 18 E5 9F F0 18`|
|`0x10`|`E5 9F F0 18 E5 9F F0 18 E5 9F F0 18 E5 9F F0 18`|
|`0x20`|`11 21 74 80 11 21 7B 20 11 21 7B 5C 11 21 7B 98`|
|`0x30`|`11 21 7B D4 11 21 7C AC 00 00 00 40 11 21 77 AC`|

---

## 2) Compute the image base and validate offsets immediately

Assume the binary is mapped at some base address `BASE`. Any pointer that targets code inside this binary should satisfy:

- `absolute = BASE + file_offset`
- therefore `file_offset = absolute - BASE`

Since the file is only `0x9D1F0` bytes:

- `0x0 <= file_offset < 0x9D1F0`

### 2.1) Pick an initial candidate base from the reset pointer

Take the reset vector pointer:

- `A = 0x11217480`

A natural first guess is that the low portion of `A` (relative to some aligned base) is the in-file offset. Here, `0x17480` is a plausible in-file offset because:

- `0x17480 < 0x9D1F0`
- it is 4-byte aligned (good for ARM code)

So we hypothesize:

- `file_offset(reset) approx 0x17480`
- `BASE approx A - 0x17480 = 0x11200000`

#### Immediate validation (before accepting the base)

Before committing to the base, validate that the hypothesized offsets point to plausible code:

- Seek to file offset `0x17480`
- Disassemble as ARM (note: all vector addresses have bit 0 clear, consistent with ARM state, not Thumb)
- Confirm it looks like real executable code (common ARM prologue patterns like `STMFD sp!, {...}`, sensible control flow, not long runs of `00` or `FF`, not obvious string or table data)

If `0x17480` does not look like code, discard this hypothesis and try a different base or alignment model.

### 2.2) Candidate base

If the reset handler offset validates, the candidate image base is:

- `BASE = 0x11200000`

### 2.3) Validate the base using the other vector pointers

For each remaining pointer `Pi` that appears to be an in-image address, compute:

- `Oi = Pi - BASE`

That yields:

| Vector | Absolute pointer | Derived file offset |
|:------:|:---------------:|:-------------------:|
| `undef` | `0x11217B20` | `0x17B20` |
| `swi` | `0x11217B5C` | `0x17B5C` |
| `prefetch_abort` | `0x11217B98` | `0x17B98` |
| `data_abort` | `0x11217BD4` | `0x17BD4` |
| `reserved` | `0x11217CAC` | `0x17CAC` |
| `fiq` | `0x112177AC` | `0x177AC` |

For each derived offset (`0x17B20`, `0x17B5C`, `0x17B98`, etc.) repeat the same validation:

- Seek to that file offset
- Confirm it disassembles as plausible ARM code and resembles a handler entry

If multiple independent vector targets land on valid code with the same `BASE`, confidence in the derived image base is very high.

---

## Special-case entry: `irq` (`0x00000040`)

The `irq` literal is `0x00000040`, which does not match the `0x112xxxxx` region. This usually means it is not a normal in-image absolute pointer like the others.

Important distinction:

- `0x40` here is an absolute memory address (`0x00000040`), not a file offset.
- It commonly refers to a stub or dispatcher located in the low vector page, which may be mapped or aliased at address `0x00000000` (or sometimes `0xFFFF0000`) on classic ARM systems.

In many firmware layouts, there is meaningful code at file offset `0x40`, and if the binary (or a small vector-page component of it) is used to populate the low vector page, that can be intentional. Regardless, because this entry does not follow the `0x112xxxxx` pattern, it is typically treated as a special case and excluded from the primary in-image base calculation.

---

## Conclusion

By:
1. extracting absolute handler addresses from the vector literal table,
2. solving `file_offset = absolute - BASE` under the constraint `0 <= file_offset < image_size`,
3. validating the derived offsets by disassembling and checking they look like real ARM code, and
4. observing consistency across multiple vector entries,

we determine the image most likely expects to be loaded at:

- `BASE = 0x11200000`