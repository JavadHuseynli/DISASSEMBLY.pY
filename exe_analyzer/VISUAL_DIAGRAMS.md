# Visual Diagrams Feature - Assembly Instructions with Graphics! 🎨

## 🎯 NEW ENHANCEMENT: Visual Memory/Register Diagrams

The Interactive Disassembly feature now includes **VISUAL DIAGRAMS** showing exactly what happens in memory and registers when an instruction executes!

## ✨ What's New

### Visual Before/After States
When you click on an instruction, you now see:
- **ASCII art diagrams** showing memory layout
- **Before and After states** of registers
- **Stack visualization** for stack operations
- **Step-by-step operation** breakdown
- **Flag changes** explained visually

## 🎨 Instructions with Visual Diagrams

### Stack Operations
- **SUB RSP, 0x28** - Shows stack allocation with memory diagram
- **PUSH** - Shows value being pushed onto stack
- **POP** - Shows value being popped from stack
- **ADD RSP** - Shows stack cleanup

### Data Movement
- **MOV** - Shows register/memory transfers
- **LEA** - Shows address calculation

### Arithmetic
- **ADD** - Shows register value changes
- **SUB** - Shows subtraction and result

### Logical Operations
- **XOR** - Shows bit-level XOR operation
  - Special: `xor rax, rax` shows why it zeros the register
- **AND** - Shows bitwise AND
- **OR** - Shows bitwise OR

### Comparison & Testing
- **CMP** - Shows flag changes without storing result
- **TEST** - Shows AND operation and flag effects

### Function Calls
- **CALL** - Shows return address being saved on stack
- **RET** - Shows return to caller

## 📖 Example: SUB RSP, 0x28

When you click on `sub rsp, 0x28`, you see:

```
BEFORE: sub rsp, 0x28        AFTER:
┌──────────────────┐         ┌──────────────────┐
│  High Memory     │         │  High Memory     │
│                  │         │                  │
│ ┌──────────────┐ │         │ ┌──────────────┐ │
│ │ Return Addr  │ │         │ │ Return Addr  │ │
│ └──────────────┘ │         │ └──────────────┘ │
│        ↑         │         │                  │
│      RSP ← 0x1000│         │ ┌──────────────┐ │ ← Stack space allocated
│                  │         │ │   40 bytes   │ │   (0x28 = 40 bytes)
│                  │         │ │   (0x28)     │ │
│                  │         │ │              │ │
│                  │         │ │  Available   │ │
│                  │         │ │  for local   │ │
│                  │         │ │  variables   │ │
│                  │         │ └──────────────┘ │
│                  │         │        ↑         │
│                  │         │      RSP ← 0xFD8 │ (0x1000 - 0x28 = 0xFD8)
│                  │         │                  │
│  Low Memory      │         │  Low Memory      │
└──────────────────┘         └──────────────────┘

REGISTER CHANGE:
  RSP = RSP - 0x28
  0x1000 - 0x28 = 0xFD8

  Stack grows DOWNWARD (towards lower addresses)
```

## 📖 Example: XOR RAX, RAX

When you click on `xor rax, rax`, you see:

```
Example: xor rax, rax (common idiom to zero register)

BEFORE:                      AFTER:
┌──────────────┐             ┌──────────────┐
│ RAX: 0x1234  │             │ RAX: 0x0000  │ ← Always zero!
└──────────────┘             └──────────────┘

WHY IT WORKS:
  Any bit XOR itself = 0
  0 XOR 0 = 0
  1 XOR 1 = 0

  Binary:
  0001 0010 0011 0100  (0x1234)
  XOR
  0001 0010 0011 0100  (0x1234)
  =
  0000 0000 0000 0000  (0x0000)

ADVANTAGES:
  • Smaller opcode than "mov rax, 0" (2 bytes vs 7 bytes)
  • Faster execution
  • Common compiler optimization
```

## 📖 Example: CALL Instruction

When you click on `call 0x401000`, you see:

```
Example: call 0x401000 (at address 0x400500)

BEFORE:                      AFTER:
Code:                        Code:
┌──────────────────┐         ┌──────────────────┐
│ 0x400500: call   │         │ RIP → 0x401000   │ ← Jumped to function
│ 0x400505: next   │         │       (function) │
└──────────────────┘         └──────────────────┘

Stack:                       Stack:
┌──────────────────┐         ┌──────────────────┐
│                  │         │ ┌──────────────┐ │
│        ↑         │         │ │  0x400505    │ │ ← Return address saved
│      RSP         │         │ └──────────────┘ │
│                  │         │        ↑         │
└──────────────────┘         │      RSP (pushed)│
                             └──────────────────┘

OPERATION:
  1. Push return address (0x400505) onto stack
  2. RSP = RSP - 8
  3. RIP = 0x401000 (jump to function)

When function executes RET, it will return to 0x400505
```

## 🚀 How to Use

### Step 1: Open and Disassemble
1. Open any .exe file (e.g., `/Users/javad/Developer/analyse/putty.exe`)
2. Click **⚙️ Disassemble** button
3. Wait for disassembly to complete

### Step 2: Click Any Instruction
In the Disassembly tab, click on any instruction:
```
0x00000000000be504  48 83 ec 28    sub    rsp, 0x28
                                   ^^^
                                Click here!
```

### Step 3: See Visual Diagram!
A help window appears with:
- Text explanation
- Syntax and examples
- **VISUAL DIAGRAM** section showing:
  - Memory layout BEFORE
  - Memory layout AFTER
  - Register changes
  - Step-by-step operation
  - Flag changes

## 💡 Why Visual Diagrams?

### For Learning
- **See** what happens, don't just read about it
- Understand stack operations visually
- Learn register changes graphically
- Grasp memory layout instantly

### For Reverse Engineering
- Quickly understand complex operations
- Visualize stack frame setup
- See function call mechanics
- Understand data flow

### For Teaching
- Visual teaching aid
- Show students exact memory changes
- Demonstrate assembly concepts
- Interactive learning tool

## 🎓 Learning Path

### Level 1: Basic Visualization
Start with simple instructions:
1. **MOV** - See data copy between registers
2. **ADD/SUB** - See arithmetic results
3. **PUSH/POP** - See stack operations

### Level 2: Stack Operations
Understand stack mechanics:
4. **SUB RSP, 0x28** - See stack allocation
5. **ADD RSP, 0x28** - See stack cleanup
6. **PUSH/POP** - See stack frame creation

### Level 3: Advanced Operations
Master complex instructions:
7. **CALL** - See return address saved
8. **RET** - See return to caller
9. **XOR** - See why `xor reg, reg` zeros register
10. **CMP/TEST** - See flag changes

## 📊 Benefits

### Visual Learning
✅ See memory changes instantly
✅ Understand stack growth/shrinkage
✅ Grasp register modifications
✅ Learn by visualization

### Faster Understanding
✅ No need to imagine memory layout
✅ Clear before/after states
✅ Step-by-step breakdown
✅ Visual flag explanations

### Educational Tool
✅ Perfect for teaching assembly
✅ Self-paced learning
✅ Interactive exploration
✅ Immediate feedback

## 🎯 Instructions with Diagrams

Currently supported (10+ instructions):
- ✅ **SUB** - Stack allocation, arithmetic
- ✅ **ADD** - Addition, stack cleanup
- ✅ **PUSH** - Stack push operation
- ✅ **POP** - Stack pop operation
- ✅ **MOV** - Data movement
- ✅ **XOR** - Bitwise XOR, zero register
- ✅ **CMP** - Comparison with flags
- ✅ **TEST** - Logical test with flags
- ✅ **CALL** - Function call mechanics
- ✅ **RET** - Return from function

More diagrams coming soon for:
- JMP, JE, JNE, JZ (conditional jumps)
- SHL, SHR, SAR (bit shifts)
- AND, OR, NOT (logical operations)
- LEA (address calculation)
- INC, DEC (increment/decrement)

## 🎉 Example Session

### Analyzing Stack Frame Creation

1. **Open putty.exe**
2. **Disassemble**
3. **Click on function prologue:**
   ```
   push rbp          ← Click: See RBP saved on stack
   mov rbp, rsp      ← Click: See stack frame setup
   sub rsp, 0x20     ← Click: See local space allocation (visual!)
   ```

4. **Click on operations:**
   ```
   mov rax, 5        ← Click: See value loaded into RAX
   add rax, 10       ← Click: See addition result (visual!)
   xor rcx, rcx      ← Click: See why it zeros RCX (visual!)
   ```

5. **Click on comparisons:**
   ```
   cmp rax, 0        ← Click: See flag changes (visual!)
   test rbx, rbx     ← Click: See AND operation (visual!)
   je error          ← Click: See conditional jump explanation
   ```

6. **Click on function epilogue:**
   ```
   add rsp, 0x20     ← Click: See stack cleanup (visual!)
   pop rbp           ← Click: See RBP restored (visual!)
   ret               ← Click: See return mechanism (visual!)
   ```

## 💻 Try It Now!

**Your example: `sub rsp, 0x28`**

1. In the running application (PID 44663)
2. Open `/Users/javad/Developer/analyse/putty.exe`
3. Click **⚙️ Disassemble**
4. Find the line: `0x00000000000be504  48 83 ec 28    sub    rsp, 0x28`
5. **Click on "sub"**
6. See the **VISUAL DIAGRAM** showing:
   - Stack BEFORE: RSP at top
   - Stack AFTER: RSP moved down by 0x28 bytes
   - 40 bytes allocated for local variables
   - Memory addresses shown (0x1000 → 0xFD8)

## 🎨 Visual Elements

### ASCII Art Components
- **Boxes** (┌─┐ └─┘) - Represent memory regions
- **Arrows** (← → ↑ ↓) - Show data flow
- **Labels** - Register names, addresses
- **Before/After** - Side-by-side comparison

### Information Displayed
- Memory addresses (hex)
- Register values (hex)
- Size calculations (0x28 = 40 bytes)
- Direction of change (arrows)
- Explanatory comments

## 📝 Summary

**You now have VISUAL ASSEMBLY EDUCATION built-in!**

✅ Click instruction → See visual diagram
✅ Before/After memory states
✅ Register changes shown graphically
✅ Stack operations visualized
✅ Flag changes explained
✅ Step-by-step breakdown
✅ Perfect for learning and analysis!

**No more guessing what `sub rsp, 0x28` does - SEE IT GRAPHICALLY!** 🎯

---

*Feature enhanced: November 2025*
*Makes assembly visual, intuitive, and easy to understand!*
*Compatible with: EXE Analyzer v1.0+*
