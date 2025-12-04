# Interactive Disassembly - Click to Learn!

## 🎯 NEW FEATURE: Interactive Instruction Explanations

The EXE Analyzer now has **INTERACTIVE DISASSEMBLY**! Just click on any assembly instruction to instantly see what it does - making reverse engineering much easier to understand!

## ✨ What's New

### 1. **Click Any Instruction**
Simply click on any assembly instruction in the disassembly view and get instant explanation!

### 2. **Detailed Help Window**
Shows comprehensive information:
- What the instruction does
- Syntax format
- Real example
- Flags it affects
- Common use cases

### 3. **Syntax Highlighting**
Color-coded disassembly for easier reading:
- 🔵 **Blue**: Addresses and bytes
- 🟢 **Green**: Mnemonics (instructions)
- 🟠 **Orange**: Registers and operands
- 🟡 **Yellow**: Immediate values

### 4. **Smart Cursor**
Hand cursor (👆) appears when hovering over clickable instructions!

## 🚀 How to Use

### Step 1: Disassemble Your File
```
1. Open any .exe file
2. Click ⚙️ Disassemble button
3. Wait for disassembly to complete
```

### Step 2: Click Any Instruction
```
In the Disassembly tab, click on any line like:
0x140001000  48 83 ec 28    sub    rsp, 0x28
                            ^^^
                         Click here!
```

### Step 3: Read the Explanation
A help window pops up showing:
```
======================================================================
  SUB - Subtract two values
======================================================================

Category: Arithmetic
Syntax: SUB dest, src

WHAT IT DOES:
  Subtracts source from destination and stores result in destination.

EXAMPLE:
  sub rsp, 0x20  ; Reserve 32 bytes on stack

AFFECTS:
  CF, PF, AF, ZF, SF, OF flags

COMMON USES:
  • Integer subtraction
  • Allocate stack space
  • Decrement by value
  • Compare values (without storing)
======================================================================
```

## 📚 Supported Instructions (50+)

### Data Movement
- **MOV** - Move data
- **LEA** - Load effective address
- **PUSH** - Push onto stack
- **POP** - Pop from stack

### Arithmetic
- **ADD** - Addition
- **SUB** - Subtraction
- **INC** - Increment
- **DEC** - Decrement
- **MUL/IMUL** - Multiply
- **DIV/IDIV** - Divide
- **NEG** - Negate

### Logical
- **AND** - Bitwise AND
- **OR** - Bitwise OR
- **XOR** - Bitwise XOR
- **NOT** - Bitwise NOT

### Shifts
- **SHL** - Shift left
- **SHR** - Shift right (unsigned)
- **SAR** - Shift arithmetic right (signed)

### Control Flow
- **JMP** - Unconditional jump
- **JE/JZ** - Jump if equal/zero
- **JNE/JNZ** - Jump if not equal/not zero
- **JG/JL** - Jump if greater/less (signed)
- **JA/JB** - Jump if above/below (unsigned)
- **CALL** - Call function
- **RET** - Return from function

### Comparison
- **CMP** - Compare values
- **TEST** - Logical compare

### String Operations
- **MOVS** - Move string
- **STOS** - Store string

### System
- **NOP** - No operation
- **INT** - Software interrupt
- **SYSCALL** - System call

## 💡 What Each Explanation Includes

### 1. **Category**
What type of instruction it is:
- Data Movement
- Arithmetic
- Logical
- Control Flow
- etc.

### 2. **Syntax**
How to use the instruction:
```
MOV dest, src
ADD dest, src
JMP target
```

### 3. **What It Does**
Plain English explanation of the operation

### 4. **Example**
Real-world usage example with comments

### 5. **Affects**
Which flags or registers are modified:
- **Flags**: CF, ZF, SF, OF, PF, AF
- **Registers**: RSP, RIP, etc.

### 6. **Common Uses**
Practical scenarios where this instruction is used

## 🎓 Learning Examples

### Example 1: Understanding Stack Allocation

**Click on:**
```
sub rsp, 0x20
```

**You'll learn:**
- SUB subtracts source from destination
- `rsp` is the stack pointer
- `0x20` is 32 bytes
- This allocates 32 bytes of stack space
- Common in function prologues

### Example 2: Understanding Zero Checks

**Click on:**
```
test rax, rax
```

**You'll learn:**
- TEST does AND without storing result
- `test rax, rax` checks if RAX is zero
- Sets Zero Flag (ZF) if RAX == 0
- Common idiom for null pointer checks

### Example 3: Understanding Function Calls

**Click on:**
```
call MessageBoxA
```

**You'll learn:**
- CALL pushes return address onto stack
- Then jumps to target function
- Used to invoke functions/APIs
- Return address saved for RET instruction

### Example 4: Understanding XOR Trick

**Click on:**
```
xor rax, rax
```

**You'll learn:**
- XOR with itself always gives zero
- Faster than `mov rax, 0`
- Smaller opcode (2 bytes vs 7 bytes)
- Common compiler optimization

## 🎯 Use Cases

### 1. **Learning Assembly**
Perfect for beginners learning x86/x64 assembly language!

**Benefits:**
- Instant feedback
- Real examples from actual programs
- No need to Google every instruction
- Learn while analyzing

### 2. **Reverse Engineering**
Understand unfamiliar code quickly

**Benefits:**
- Refresh memory on rarely-used instructions
- Understand complex instruction combinations
- Learn what flags are affected
- See common usage patterns

### 3. **Malware Analysis**
Quickly understand suspicious code

**Benefits:**
- Identify obfuscation techniques
- Understand shellcode
- Recognize common malware patterns
- Learn anti-analysis tricks

### 4. **Education**
Perfect for students and teachers

**Benefits:**
- Interactive learning tool
- Self-paced education
- Visual and textual learning
- Practical examples

## 📖 Example Session

### Analyzing a Function

1. **Disassemble putty.exe**
2. **Click on function prologue:**
   ```
   push rbp          ← Click: See it saves base pointer
   mov rbp, rsp      ← Click: See it sets up stack frame
   sub rsp, 0x20     ← Click: See it allocates local space
   ```

3. **Click on calculations:**
   ```
   mov rax, 5        ← Click: See how to load immediate
   add rax, 10       ← Click: See how addition works
   imul rax, rbx     ← Click: See signed multiplication
   ```

4. **Click on conditionals:**
   ```
   cmp rax, 0        ← Click: See how comparison works
   je error_handler  ← Click: See conditional jump
   ```

5. **Click on function epilogue:**
   ```
   add rsp, 0x20     ← Click: See stack cleanup
   pop rbp           ← Click: See base pointer restore
   ret               ← Click: See function return
   ```

## 🎨 Visual Enhancements

### Color Coding
```
Address           Bytes               Mnemonic    Operands
🔵 Gray          🔵 Blue              🟢 Green    🟠 Orange
0x140001000     48 83 ec 28          sub         rsp, 0x28
```

### Hover Effect
- **Normal cursor** (I-beam) on regular text
- **Hand cursor** (👆) on clickable instructions

### Help Window
- **Dark themed** for comfortable reading
- **Color-coded** sections for easy scanning
- **Stay on top** option for reference
- **Resizable** and repositionable

## 🔥 Pro Tips

### Tip 1: Keep Help Window Open
Leave the help window open while analyzing. It updates when you click different instructions!

### Tip 2: Learn Common Patterns
Look for patterns like:
```
push rbp
mov rbp, rsp
sub rsp, 0x20
```
This is a standard function prologue!

### Tip 3: Understand Flags
Pay attention to "AFFECTS" section to understand how instructions change CPU flags for conditional jumps.

### Tip 4: Learn Idioms
Common idioms explained:
- `xor reg, reg` → Zero out register
- `test reg, reg` → Check if zero
- `or reg, reg` → Test for zero
- `lea rax, [rax*4]` → Multiply by 4

### Tip 5: Compare Similar Instructions
Click on similar instructions to understand differences:
- `JE` vs `JZ` (same thing!)
- `SHR` vs `SAR` (unsigned vs signed)
- `MUL` vs `IMUL` (unsigned vs signed)

## 📊 Benefits

### For Beginners
✅ Learn assembly interactively
✅ No need to memorize everything
✅ See real-world examples
✅ Understand immediately

### For Professionals
✅ Quick reference tool
✅ Refresh memory instantly
✅ Understand unfamiliar code
✅ Teach others effectively

### For Students
✅ Study aid for exams
✅ Homework helper
✅ Project assistance
✅ Self-paced learning

### For Educators
✅ Teaching tool
✅ Demonstration aid
✅ Interactive examples
✅ Engage students

## 🎓 Learning Path

### Level 1: Basic Instructions
Start by clicking:
1. `mov` - Data movement
2. `add` / `sub` - Basic arithmetic
3. `push` / `pop` - Stack operations

### Level 2: Logic & Comparison
Then learn:
4. `and` / `or` / `xor` - Bitwise ops
5. `cmp` / `test` - Comparisons
6. `jmp` / `je` / `jne` - Conditional jumps

### Level 3: Advanced
Finally master:
7. `lea` - Address calculation
8. `call` / `ret` - Function calls
9. `shl` / `shr` - Bit shifts
10. `imul` / `idiv` - Multiplication/division

## 🚀 Quick Start

**Try it NOW:**

1. **Open putty.exe**
   ```
   File → Open → Select putty.exe
   ```

2. **Disassemble**
   ```
   Click ⚙️ Disassemble button
   ```

3. **Click any instruction!**
   ```
   Click on "mov", "add", "sub", etc.
   See instant explanation!
   ```

## 📝 Example Output

### Clicking on "MOV RAX, 5"

```
======================================================================
  MOV - Move data from source to destination
======================================================================

Category: Data Movement
Syntax: MOV dest, src

WHAT IT DOES:
  Copies the value from the source operand to the destination.
  Does not affect flags.

EXAMPLE:
  mov rax, 5  ; Put value 5 into RAX register

AFFECTS:
  None

COMMON USES:
  • Initialize registers
  • Copy values between registers
  • Load values from memory
  • Store values to memory

======================================================================
💡 TIP: Click any instruction in disassembly to see its explanation!
======================================================================

You clicked:
  0x0000000140001234  b8 05 00 00 00    mov    rax, 5
======================================================================
```

## 🎉 Summary

**You now have an INTERACTIVE ASSEMBLY TUTOR built into the disassembler!**

✅ Click any instruction → Instant explanation
✅ 50+ instructions documented
✅ Syntax highlighting
✅ Real examples
✅ Common use cases
✅ Flags affected
✅ Perfect for learning!

**No more Googling "what does sub rsp 0x20 mean?" - just click it!** 🎯

---

*Feature added: November 2025*
*Makes reverse engineering educational and fun!*
*Compatible with: EXE Analyzer v1.0+*
