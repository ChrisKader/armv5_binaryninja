# ARM Thumb Decomposer/Disassembler
This is a disassembler for ARM Thumb (16-bit only, ARMv4T/ARMv5T). It does not contain Thumb-2 or ThumbEE.

# Terms
I'm using "Decomposer" to mean that instruction data is analyzed and a useful description of that instruction data is produced.
More specific, an "instruction info" struct is created, capturing information about the instruction like its source registers and such.
I'm using "Disassembler" to mean that this "instruction info" struct from the decompose stage can be parsed to generated a human readable string that we commonly associate with disassembly.
This contains the instruction mnemonic and operands and any annotations (like the S suffix or condition flag).

# High Level Strategy
Capture as much as possible from the specification (ARM Architecture Reference Manual, ARMv5 edition).
Currently that's being done in spec.txt.
Then, parse that information (see generator.py) into C++ source (see spec.cpp).
Finally, add another source file that calls into spec.cpp to interface with the rest of Binary Ninja.

# Lower Level Strategy
The tables of instructions become nodes in a graph.
When one table refers to another, that's an edge to another table.
And when a table holds only references to instruction encodings, it's a terminal node.
So decomposing/disassembling is traversing the graph from root to tip.
The intermediate language used to capture this table/node info kind of gets into a tradeoff game.
On one hand, I want to be able to copy/paste as much as possible from the spec.
On the other, I want the language to be simple enough that I don't need to recall anything from CompSci to write a simple parser for it.
The parser can be written in a nice easy language too; here, python.

# How To Actually Generate?
Just run generator.py. It will read spec.txt and write spec.cpp.

# Notes
- 's' suffix on instructions means it updates the flags
- cmp,cmn,tst,teq are result-less forms of subs,adds,ands,eors, but only update flags (but don't require the extra 's' suffix)
- there are 4 flags N,Z,C,V for negative,zero,carry,overflow
- the 'c' on b<c> is a conditional execution code (14 total) that test the flags
  - code can be 'eq', 'ne', 'cs'/'hs', 'cc'/'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al'/''

