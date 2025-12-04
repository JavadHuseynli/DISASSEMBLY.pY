"""
Instruction Help Database - Explanations for x86/x64 Assembly Instructions
Provides detailed explanations when user clicks on disassembly
"""

class InstructionHelper:
    """Database of assembly instruction explanations"""

    def __init__(self):
        self.instructions = {
            # Data Movement
            'mov': {
                'category': 'Data Movement',
                'description': 'Move data from source to destination',
                'syntax': 'MOV dest, src',
                'example': 'mov rax, 5  ; Put value 5 into RAX register',
                'explanation': 'Copies the value from the source operand to the destination. Does not affect flags.',
                'affects': 'None',
                'common_uses': [
                    'Initialize registers',
                    'Copy values between registers',
                    'Load values from memory',
                    'Store values to memory'
                ],
                'visual_diagram': '''
Example: mov rax, rbx

BEFORE:                      AFTER:
┌──────────────┐             ┌──────────────┐
│ RAX: 0x0000  │             │ RAX: 0x1234  │ ← Copied from RBX
└──────────────┘             └──────────────┘
┌──────────────┐             ┌──────────────┐
│ RBX: 0x1234  │             │ RBX: 0x1234  │ (unchanged)
└──────────────┘             └──────────────┘

OPERATION:
  RAX = RBX    (copy value)

Example 2: mov rax, [rbx] (load from memory)

Memory at RBX (0x5000):      Registers:
┌──────────────┐             ┌──────────────┐
│ 0x5000: 0xABCD│            │ RAX: 0xABCD  │ ← Loaded from [RBX]
└──────────────┘             └──────────────┘
                             ┌──────────────┐
                             │ RBX: 0x5000  │ (address)
                             └──────────────┘
'''
            },
            'lea': {
                'category': 'Data Movement',
                'description': 'Load Effective Address',
                'syntax': 'LEA dest, [address]',
                'example': 'lea rax, [rbx+8]  ; Load address (RBX+8) into RAX',
                'explanation': 'Loads the calculated address into the destination, not the value at that address. Useful for pointer arithmetic.',
                'affects': 'None',
                'common_uses': [
                    'Calculate addresses',
                    'Fast multiplication (lea rax, [rax*4])',
                    'Get address of local variables',
                    'Pointer arithmetic'
                ]
            },
            'push': {
                'category': 'Stack',
                'description': 'Push value onto stack',
                'syntax': 'PUSH src',
                'example': 'push rax  ; Push RAX onto stack',
                'explanation': 'Decrements stack pointer (RSP) and stores value at new stack location.',
                'affects': 'RSP (stack pointer)',
                'common_uses': [
                    'Save registers before function call',
                    'Pass parameters to functions',
                    'Save state',
                    'Create stack frame'
                ],
                'visual_diagram': '''
BEFORE: push rax             AFTER:
┌──────────────────┐         ┌──────────────────┐
│  High Memory     │         │  High Memory     │
│                  │         │                  │
│                  │         │ ┌──────────────┐ │
│                  │         │ │ RAX = 0x1234 │ │ ← Value pushed here
│                  │         │ └──────────────┘ │
│        ↑         │         │        ↑         │
│      RSP ← 0x1000│         │      RSP ← 0xFF8 │ (RSP decreased by 8)
│                  │         │                  │
│  Low Memory      │         │  Low Memory      │
└──────────────────┘         └──────────────────┘

Register: RAX = 0x1234

OPERATION:
  1. RSP = RSP - 8    (stack pointer moves down)
  2. [RSP] = RAX      (store RAX value at new RSP)

  Stack grows DOWNWARD (push decreases RSP)
'''
            },
            'pop': {
                'category': 'Stack',
                'description': 'Pop value from stack',
                'syntax': 'POP dest',
                'example': 'pop rax  ; Pop stack value into RAX',
                'explanation': 'Loads value from current stack location into destination and increments stack pointer.',
                'affects': 'RSP (stack pointer)',
                'common_uses': [
                    'Restore saved registers',
                    'Clean up stack',
                    'Return from function',
                    'Retrieve saved values'
                ],
                'visual_diagram': '''
BEFORE: pop rax              AFTER:
┌──────────────────┐         ┌──────────────────┐
│  High Memory     │         │  High Memory     │
│                  │         │                  │
│ ┌──────────────┐ │         │ ┌──────────────┐ │
│ │  0x5678      │ │         │ │  0x5678      │ │ (value still in memory)
│ └──────────────┘ │         │ └──────────────┘ │
│        ↑         │         │                  │
│      RSP ← 0xFF8 │         │        ↑         │
│                  │         │      RSP ← 0x1000│ (RSP increased by 8)
│  Low Memory      │         │  Low Memory      │
└──────────────────┘         └──────────────────┘

Register RAX:
  BEFORE: 0x????
  AFTER:  0x5678 ← Value from stack

OPERATION:
  1. RAX = [RSP]      (load value from stack)
  2. RSP = RSP + 8    (stack pointer moves up)

  Stack shrinks UPWARD (pop increases RSP)
'''
            },

            # Arithmetic
            'add': {
                'category': 'Arithmetic',
                'description': 'Add two values',
                'syntax': 'ADD dest, src',
                'example': 'add rax, 5  ; RAX = RAX + 5',
                'explanation': 'Adds source to destination and stores result in destination.',
                'affects': 'CF, PF, AF, ZF, SF, OF flags',
                'common_uses': [
                    'Integer addition',
                    'Increment by value',
                    'Pointer arithmetic',
                    'Loop counters'
                ],
                'visual_diagram': '''
Example: add rax, 0x10

BEFORE:                      AFTER:
┌──────────────┐             ┌──────────────┐
│ RAX: 0x0005  │             │ RAX: 0x0015  │ ← Result (5 + 16 = 21)
└──────────────┘             └──────────────┘

OPERATION:
  RAX = RAX + 0x10
  5 + 16 = 21 (decimal)
  0x5 + 0x10 = 0x15 (hex)

FLAGS AFFECTED:
  CF = Carry flag (set if unsigned overflow)
  ZF = Zero flag (set if result is 0)
  SF = Sign flag (set if result is negative)
  OF = Overflow flag (set if signed overflow)

Example 2: add rsp, 0x20 (clean up stack)
┌──────────────────┐         ┌──────────────────┐
│      RSP: 0xFE0  │         │      RSP: 0x1000 │ ← Stack cleaned up
└──────────────────┘         └──────────────────┘
'''
            },
            'sub': {
                'category': 'Arithmetic',
                'description': 'Subtract two values',
                'syntax': 'SUB dest, src',
                'example': 'sub rsp, 0x20  ; Reserve 32 bytes on stack',
                'explanation': 'Subtracts source from destination and stores result in destination.',
                'affects': 'CF, PF, AF, ZF, SF, OF flags',
                'common_uses': [
                    'Integer subtraction',
                    'Allocate stack space',
                    'Decrement by value',
                    'Compare values (without storing)'
                ],
                'visual_diagram': '''
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
'''
            },
            'inc': {
                'category': 'Arithmetic',
                'description': 'Increment by 1',
                'syntax': 'INC dest',
                'example': 'inc rcx  ; RCX = RCX + 1',
                'explanation': 'Adds 1 to the destination operand.',
                'affects': 'PF, AF, ZF, SF, OF flags (not CF)',
                'common_uses': [
                    'Loop counters',
                    'Array indexing',
                    'Increment variables'
                ]
            },
            'dec': {
                'category': 'Arithmetic',
                'description': 'Decrement by 1',
                'syntax': 'DEC dest',
                'example': 'dec rcx  ; RCX = RCX - 1',
                'explanation': 'Subtracts 1 from the destination operand.',
                'affects': 'PF, AF, ZF, SF, OF flags (not CF)',
                'common_uses': [
                    'Loop counters',
                    'Countdown',
                    'Decrement variables'
                ]
            },
            'mul': {
                'category': 'Arithmetic',
                'description': 'Unsigned multiply',
                'syntax': 'MUL src',
                'example': 'mul rbx  ; RAX = RAX * RBX (unsigned)',
                'explanation': 'Multiplies RAX by source (unsigned). Result in RDX:RAX (64-bit).',
                'affects': 'CF, OF flags (undefined for others)',
                'common_uses': [
                    'Unsigned multiplication',
                    'Size calculations',
                    'Array element addressing'
                ]
            },
            'imul': {
                'category': 'Arithmetic',
                'description': 'Signed multiply',
                'syntax': 'IMUL dest, src',
                'example': 'imul rax, rbx  ; RAX = RAX * RBX (signed)',
                'explanation': 'Signed multiplication. Can have 1, 2, or 3 operands.',
                'affects': 'CF, OF flags',
                'common_uses': [
                    'Signed multiplication',
                    'Integer math',
                    'Fast multiply by constant'
                ]
            },
            'div': {
                'category': 'Arithmetic',
                'description': 'Unsigned divide',
                'syntax': 'DIV src',
                'example': 'div rbx  ; RAX = RDX:RAX / RBX (unsigned)',
                'explanation': 'Divides RDX:RAX by source. Quotient in RAX, remainder in RDX.',
                'affects': 'All flags undefined',
                'common_uses': [
                    'Unsigned division',
                    'Modulo operation (remainder)',
                    'Integer division'
                ]
            },
            'idiv': {
                'category': 'Arithmetic',
                'description': 'Signed divide',
                'syntax': 'IDIV src',
                'example': 'idiv rbx  ; RAX = RDX:RAX / RBX (signed)',
                'explanation': 'Signed division. Quotient in RAX, remainder in RDX.',
                'affects': 'All flags undefined',
                'common_uses': [
                    'Signed division',
                    'Modulo with sign',
                    'Integer division'
                ]
            },

            # Logical
            'and': {
                'category': 'Logical',
                'description': 'Bitwise AND',
                'syntax': 'AND dest, src',
                'example': 'and rax, 0xFF  ; Keep only low 8 bits',
                'explanation': 'Performs bitwise AND operation. Result in destination.',
                'affects': 'CF=0, OF=0, PF, ZF, SF flags',
                'common_uses': [
                    'Clear specific bits',
                    'Test bit flags',
                    'Mask values',
                    'Align addresses'
                ]
            },
            'or': {
                'category': 'Logical',
                'description': 'Bitwise OR',
                'syntax': 'OR dest, src',
                'example': 'or rax, rax  ; Test if RAX is zero',
                'explanation': 'Performs bitwise OR operation. Result in destination.',
                'affects': 'CF=0, OF=0, PF, ZF, SF flags',
                'common_uses': [
                    'Set specific bits',
                    'Combine bit flags',
                    'Test for zero (or reg, reg)',
                    'Merge values'
                ]
            },
            'xor': {
                'category': 'Logical',
                'description': 'Bitwise XOR (Exclusive OR)',
                'syntax': 'XOR dest, src',
                'example': 'xor rax, rax  ; Zero out RAX (RAX = 0)',
                'explanation': 'Performs bitwise XOR. Common idiom: xor reg, reg sets register to zero.',
                'affects': 'CF=0, OF=0, PF, ZF, SF flags',
                'common_uses': [
                    'Zero out register (xor reg, reg)',
                    'Toggle bits',
                    'Simple encryption',
                    'Compare if equal'
                ],
                'visual_diagram': '''
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

Example 2: xor al, 0xFF (flip all bits)
┌──────────────┐             ┌──────────────┐
│ AL: 0b10101010│            │ AL: 0b01010101│ ← Bits flipped
└──────────────┘             └──────────────┘
'''
            },
            'not': {
                'category': 'Logical',
                'description': 'Bitwise NOT (complement)',
                'syntax': 'NOT dest',
                'example': 'not rax  ; Flip all bits in RAX',
                'explanation': 'Inverts all bits in the operand (1s become 0s, 0s become 1s).',
                'affects': 'None',
                'common_uses': [
                    'Bit inversion',
                    'Create bit masks',
                    'Negate value (with inc)'
                ]
            },
            'neg': {
                'category': 'Arithmetic',
                'description': 'Two\'s complement negation',
                'syntax': 'NEG dest',
                'example': 'neg rax  ; RAX = -RAX',
                'explanation': 'Converts value to its two\'s complement (arithmetic negation).',
                'affects': 'CF, PF, AF, ZF, SF, OF flags',
                'common_uses': [
                    'Negate signed numbers',
                    'Change sign',
                    'Absolute value calculation'
                ]
            },

            # Shift/Rotate
            'shl': {
                'category': 'Shift',
                'description': 'Shift Left',
                'syntax': 'SHL dest, count',
                'example': 'shl rax, 2  ; RAX = RAX * 4 (shift left 2 bits)',
                'explanation': 'Shifts bits left, filling with zeros. Each shift left multiplies by 2.',
                'affects': 'CF (last bit shifted out), OF, PF, ZF, SF',
                'common_uses': [
                    'Fast multiplication by power of 2',
                    'Bit manipulation',
                    'Align addresses',
                    'Create bit masks'
                ]
            },
            'shr': {
                'category': 'Shift',
                'description': 'Shift Right (unsigned)',
                'syntax': 'SHR dest, count',
                'example': 'shr rax, 1  ; RAX = RAX / 2 (unsigned)',
                'explanation': 'Shifts bits right, filling with zeros. Each shift right divides by 2 (unsigned).',
                'affects': 'CF (last bit shifted out), OF, PF, ZF, SF',
                'common_uses': [
                    'Fast unsigned division by power of 2',
                    'Extract high bits',
                    'Bit manipulation'
                ]
            },
            'sar': {
                'category': 'Shift',
                'description': 'Shift Arithmetic Right (signed)',
                'syntax': 'SAR dest, count',
                'example': 'sar rax, 1  ; RAX = RAX / 2 (signed)',
                'explanation': 'Shifts bits right, preserving sign bit. Used for signed division by 2.',
                'affects': 'CF (last bit shifted out), OF, PF, ZF, SF',
                'common_uses': [
                    'Fast signed division by power of 2',
                    'Preserve sign when shifting',
                    'Signed arithmetic'
                ]
            },

            # Control Flow
            'jmp': {
                'category': 'Control Flow',
                'description': 'Unconditional jump',
                'syntax': 'JMP target',
                'example': 'jmp 0x401000  ; Jump to address 0x401000',
                'explanation': 'Transfers control to the target address unconditionally.',
                'affects': 'None',
                'common_uses': [
                    'Goto statements',
                    'Loop implementation',
                    'Skip code sections',
                    'Function trampolines'
                ]
            },
            'je': {
                'category': 'Control Flow',
                'description': 'Jump if Equal (ZF=1)',
                'syntax': 'JE target',
                'example': 'cmp rax, 5\nje equal_label  ; Jump if RAX == 5',
                'explanation': 'Jumps if Zero Flag is set (usually after comparison shows equality).',
                'affects': 'None',
                'common_uses': [
                    'If statements (if equal)',
                    'Switch statements',
                    'Loop conditions',
                    'Validate input'
                ]
            },
            'jne': {
                'category': 'Control Flow',
                'description': 'Jump if Not Equal (ZF=0)',
                'syntax': 'JNE target',
                'example': 'test rax, rax\njne not_zero  ; Jump if RAX != 0',
                'explanation': 'Jumps if Zero Flag is clear (comparison shows inequality).',
                'affects': 'None',
                'common_uses': [
                    'If statements (if not equal)',
                    'Loop conditions',
                    'Error checking',
                    'Null pointer checks'
                ]
            },
            'jz': {
                'category': 'Control Flow',
                'description': 'Jump if Zero (ZF=1)',
                'syntax': 'JZ target',
                'example': 'test rax, rax\njz is_zero  ; Jump if RAX is zero',
                'explanation': 'Same as JE. Jumps if Zero Flag is set.',
                'affects': 'None',
                'common_uses': [
                    'Test for zero',
                    'Null checks',
                    'Loop termination'
                ]
            },
            'jnz': {
                'category': 'Control Flow',
                'description': 'Jump if Not Zero (ZF=0)',
                'syntax': 'JNZ target',
                'example': 'dec rcx\njnz loop_top  ; Continue loop if RCX != 0',
                'explanation': 'Same as JNE. Jumps if Zero Flag is clear.',
                'affects': 'None',
                'common_uses': [
                    'Loop implementation',
                    'Check non-zero',
                    'Validate return values'
                ]
            },
            'jg': {
                'category': 'Control Flow',
                'description': 'Jump if Greater (signed)',
                'syntax': 'JG target',
                'example': 'cmp rax, 10\njg greater  ; Jump if RAX > 10 (signed)',
                'explanation': 'Jumps if signed comparison shows first operand is greater.',
                'affects': 'None',
                'common_uses': [
                    'If statements (greater than)',
                    'Range checking',
                    'Sorted data processing'
                ]
            },
            'jl': {
                'category': 'Control Flow',
                'description': 'Jump if Less (signed)',
                'syntax': 'JL target',
                'example': 'cmp rax, 0\njl negative  ; Jump if RAX < 0 (signed)',
                'explanation': 'Jumps if signed comparison shows first operand is less.',
                'affects': 'None',
                'common_uses': [
                    'If statements (less than)',
                    'Range checking',
                    'Sign testing'
                ]
            },
            'ja': {
                'category': 'Control Flow',
                'description': 'Jump if Above (unsigned)',
                'syntax': 'JA target',
                'example': 'cmp rax, 100\nja above  ; Jump if RAX > 100 (unsigned)',
                'explanation': 'Jumps if unsigned comparison shows first operand is above.',
                'affects': 'None',
                'common_uses': [
                    'Unsigned comparisons',
                    'Array bounds checking',
                    'Size validation'
                ]
            },
            'jb': {
                'category': 'Control Flow',
                'description': 'Jump if Below (unsigned)',
                'syntax': 'JB target',
                'example': 'cmp rax, 10\njb below  ; Jump if RAX < 10 (unsigned)',
                'explanation': 'Jumps if unsigned comparison shows first operand is below.',
                'affects': 'None',
                'common_uses': [
                    'Unsigned comparisons',
                    'Array bounds checking',
                    'Size validation'
                ]
            },

            # Comparison
            'cmp': {
                'category': 'Comparison',
                'description': 'Compare two values',
                'syntax': 'CMP dest, src',
                'example': 'cmp rax, 0  ; Compare RAX with 0',
                'explanation': 'Subtracts source from destination and sets flags, but doesn\'t store result. Used before conditional jumps.',
                'affects': 'CF, PF, AF, ZF, SF, OF flags',
                'common_uses': [
                    'Before conditional jumps',
                    'Value testing',
                    'Range checking',
                    'Equality testing'
                ],
                'visual_diagram': '''
Example: cmp rax, 5

BEFORE:                      AFTER:
┌──────────────┐             ┌──────────────┐
│ RAX: 0x0005  │             │ RAX: 0x0005  │ ← UNCHANGED!
└──────────────┘             └──────────────┘

FLAGS (what CMP actually does):
  Performs: RAX - 5 (but doesn't store result)
  5 - 5 = 0

  ZF = 1  (Zero Flag SET because result is 0)
  CF = 0  (Carry Flag clear)
  SF = 0  (Sign Flag clear)

TYPICAL USAGE:
┌────────────────────────────┐
│  cmp rax, 5                │ Compare RAX with 5
│  je equal_label            │ Jump if Equal (ZF=1)
│  jg greater_label          │ Jump if Greater
│  jl less_label             │ Jump if Less
└────────────────────────────┘

Example 2: cmp rax, 10 (when RAX = 5)
  Performs: 5 - 10 = -5
  ZF = 0  (not equal)
  SF = 1  (result is negative, so RAX < 10)
  CF = 1  (borrow occurred, RAX is below 10 unsigned)

CMP is like SUB but doesn't save the result!
'''
            },
            'test': {
                'category': 'Comparison',
                'description': 'Logical compare (AND without storing)',
                'syntax': 'TEST dest, src',
                'example': 'test rax, rax  ; Test if RAX is zero',
                'explanation': 'Performs AND operation and sets flags, but doesn\'t store result. Common idiom: test reg, reg checks if register is zero.',
                'affects': 'CF=0, OF=0, PF, ZF, SF flags',
                'common_uses': [
                    'Test for zero (test reg, reg)',
                    'Test specific bits',
                    'Check flags',
                    'Null pointer checks'
                ],
                'visual_diagram': '''
Example: test rax, rax (check if RAX is zero)

BEFORE:                      AFTER:
┌──────────────┐             ┌──────────────┐
│ RAX: 0x0000  │             │ RAX: 0x0000  │ ← UNCHANGED!
└──────────────┘             └──────────────┘

FLAGS:
  Performs: RAX AND RAX (but doesn't store)
  0x0000 AND 0x0000 = 0x0000

  ZF = 1  (Zero Flag SET → RAX is zero!)
  CF = 0  (always cleared by TEST)
  OF = 0  (always cleared by TEST)

TYPICAL USAGE (null pointer check):
┌────────────────────────────┐
│  test rax, rax             │ Check if RAX is null
│  jz is_null                │ Jump if Zero (RAX == 0)
│  jnz not_null              │ Jump if Not Zero (RAX != 0)
└────────────────────────────┘

Example 2: test rax, rax (when RAX = 0x1234)
┌──────────────┐
│ RAX: 0x1234  │
└──────────────┘
  0x1234 AND 0x1234 = 0x1234 (non-zero)
  ZF = 0  (not zero, RAX has value)

Example 3: test al, 0x01 (check bit 0)
  Check if lowest bit is set
  If AL = 0b00000001: ZF = 0 (bit is set)
  If AL = 0b00000000: ZF = 1 (bit is clear)

TEST is like AND but doesn't save the result!
'''
            },

            # Function Calls
            'call': {
                'category': 'Control Flow',
                'description': 'Call subroutine/function',
                'syntax': 'CALL target',
                'example': 'call MessageBoxA  ; Call MessageBoxA function',
                'explanation': 'Pushes return address onto stack and jumps to target. Used to call functions.',
                'affects': 'RSP (stack pointer)',
                'common_uses': [
                    'Function calls',
                    'API calls',
                    'Subroutine invocation',
                    'Indirect calls via register'
                ],
                'visual_diagram': '''
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
'''
            },
            'ret': {
                'category': 'Control Flow',
                'description': 'Return from subroutine/function',
                'syntax': 'RET [value]',
                'example': 'ret  ; Return to caller',
                'explanation': 'Pops return address from stack and jumps to it. Optionally cleans up stack.',
                'affects': 'RSP (stack pointer)',
                'common_uses': [
                    'Return from function',
                    'End of subroutine',
                    'Function epilogue'
                ],
                'visual_diagram': '''
Example: ret (return from function)

BEFORE:                      AFTER:
Stack:                       Stack:
┌──────────────────┐         ┌──────────────────┐
│ ┌──────────────┐ │         │ ┌──────────────┐ │
│ │  0x400505    │ │         │ │  0x400505    │ │ (value still there)
│ └──────────────┘ │         │ └──────────────┘ │
│        ↑         │         │                  │
│      RSP         │         │        ↑         │
│                  │         │      RSP (popped)│
└──────────────────┘         └──────────────────┘

Code:                        Code:
┌──────────────────┐         ┌──────────────────┐
│ RIP → 0x401000   │         │ RIP → 0x400505   │ ← Returned to caller
│       (in func)  │         │       (caller)   │
└──────────────────┘         └──────────────────┘

OPERATION:
  1. RIP = [RSP]      (pop return address)
  2. RSP = RSP + 8    (restore stack pointer)
  3. Jump to return address

This is the opposite of CALL
'''
            },

            # String Operations
            'movs': {
                'category': 'String',
                'description': 'Move String',
                'syntax': 'MOVSB/MOVSW/MOVSD/MOVSQ',
                'example': 'rep movsb  ; Copy string byte by byte',
                'explanation': 'Copies data from [RSI] to [RDI], increments both. Used with REP prefix for memory copy.',
                'affects': 'RSI, RDI',
                'common_uses': [
                    'Memory copy (memcpy)',
                    'String operations',
                    'Buffer copying'
                ]
            },
            'stos': {
                'category': 'String',
                'description': 'Store String',
                'syntax': 'STOSB/STOSW/STOSD/STOSQ',
                'example': 'rep stosb  ; Fill memory with AL value',
                'explanation': 'Stores AL/AX/EAX/RAX at [RDI] and increments RDI. Used with REP for memset.',
                'affects': 'RDI',
                'common_uses': [
                    'Memory fill (memset)',
                    'Initialize buffers',
                    'Clear memory'
                ]
            },

            # No Operation
            'nop': {
                'category': 'Other',
                'description': 'No Operation',
                'syntax': 'NOP',
                'example': 'nop  ; Do nothing',
                'explanation': 'Does nothing. Used for padding, alignment, or as placeholder. Can be multi-byte for alignment.',
                'affects': 'None',
                'common_uses': [
                    'Code alignment',
                    'Padding',
                    'Placeholder for patching',
                    'Timing adjustments'
                ]
            },

            # System
            'int': {
                'category': 'System',
                'description': 'Software interrupt',
                'syntax': 'INT number',
                'example': 'int 0x80  ; Linux system call (32-bit)',
                'explanation': 'Triggers a software interrupt. Used for system calls in some OSes.',
                'affects': 'All (switches to kernel mode)',
                'common_uses': [
                    'System calls (older)',
                    'BIOS calls (16-bit)',
                    'Debugging (int 3)'
                ]
            },
            'syscall': {
                'category': 'System',
                'description': 'System call (64-bit)',
                'syntax': 'SYSCALL',
                'example': 'syscall  ; Invoke kernel (Linux/BSD)',
                'explanation': 'Fast system call mechanism for 64-bit mode. Switches to kernel mode.',
                'affects': 'RCX, R11 (saved RIP and RFLAGS)',
                'common_uses': [
                    'Linux system calls (64-bit)',
                    'Read/write files',
                    'Network operations',
                    'Process management'
                ]
            },
        }

    def get_instruction_help(self, mnemonic):
        """Get help for an instruction"""
        mnemonic = mnemonic.lower().strip()

        # Handle variations
        if mnemonic in ['jz', 'jnz']:
            mnemonic = 'je' if mnemonic == 'jz' else 'jne'

        if mnemonic in self.instructions:
            return self.instructions[mnemonic]

        # Return generic help if not found
        return {
            'category': 'Unknown',
            'description': f'Instruction: {mnemonic.upper()}',
            'syntax': f'{mnemonic.upper()} operands',
            'example': 'No example available',
            'explanation': 'Detailed explanation not available for this instruction.',
            'affects': 'Unknown',
            'common_uses': ['Consult x86/x64 reference manual for details']
        }

    def format_help(self, help_data):
        """Format help data for display"""
        lines = []
        lines.append("═" * 70)
        lines.append(f"  {help_data['description'].upper()}")
        lines.append("═" * 70)
        lines.append("")
        lines.append(f"Category: {help_data['category']}")
        lines.append(f"Syntax: {help_data['syntax']}")
        lines.append("")
        lines.append("EXPLANATION:")
        lines.append(f"  {help_data['explanation']}")
        lines.append("")
        lines.append("EXAMPLE:")
        lines.append(f"  {help_data['example']}")
        lines.append("")
        lines.append(f"AFFECTS: {help_data['affects']}")
        lines.append("")
        lines.append("COMMON USES:")
        for use in help_data['common_uses']:
            lines.append(f"  • {use}")
        lines.append("")

        # Add visual diagram if available
        if 'visual_diagram' in help_data and help_data['visual_diagram']:
            lines.append("═" * 70)
            lines.append("  VISUAL DIAGRAM - HOW IT WORKS IN MEMORY/REGISTERS")
            lines.append("═" * 70)
            lines.append(help_data['visual_diagram'])
            lines.append("═" * 70)
        else:
            lines.append("═" * 70)

        return "\n".join(lines)
