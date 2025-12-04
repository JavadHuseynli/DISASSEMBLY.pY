# Quick Solution - Get Test .EXE Files NOW!

## Problem
You're getting "No file loaded" because the EXE Analyzer needs **Windows PE files** (.exe/.dll), but you're on macOS.

## ✅ FASTEST SOLUTION (Choose One)

### Option 1: Download PuTTY (Safe, legitimate Windows program)
```bash
cd ~/Downloads
curl -L "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe" -o putty.exe

# Verify it's a PE file
file putty.exe
# Should show: "PE32+ executable"
```

Then analyze it:
```bash
cd ~/Developer/analyse/exe_analyzer
python main.py
# Click "Open" and select ~/Downloads/putty.exe
```

### Option 2: Download 7-Zip
```bash
cd ~/Downloads
curl -L "https://www.7-zip.org/a/7z2408-x64.exe" -o 7zip-installer.exe

# Analyze it
cd ~/Developer/analyse/exe_analyzer
python main.py
# Click "Open" and select 7zip-installer.exe
```

### Option 3: Use Python to Create a Simple PE File

Create a basic PE file using pefile library:

```bash
cd ~/Developer/analyse
python3 << 'EOF'
import pefile
import struct

# Create minimal PE data
dos_header = bytearray(b'MZ' + b'\x90' * 58 + struct.pack('<I', 64))
pe_header = b'PE\x00\x00'

# Write to file
with open('test_simple.exe', 'wb') as f:
    f.write(dos_header + pe_header + b'\x00' * 400)

print("✓ Created test_simple.exe")
print("  File: test_simple.exe")
print("  Location: ~/Developer/analyse/")
EOF
```

Then analyze it:
```bash
cd exe_analyzer
python main.py
# Open ../test_simple.exe
```

## 🎯 RECOMMENDED: Download PuTTY

**This is the easiest and safest option:**

1. Run this command:
```bash
curl -L "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe" -o ~/Downloads/putty.exe
```

2. Launch EXE Analyzer:
```bash
cd ~/Developer/analyse/exe_analyzer
python main.py
```

3. In the GUI:
   - Click "📁 Open" button
   - Navigate to ~/Downloads/
   - Select putty.exe
   - Watch the analysis!

## What You'll See

Once you open a valid .exe file, the analyzer will show:

### ✅ File Information Panel (Left)
```
FILE INFORMATION
========================================
File: putty.exe
Size: 123,456 bytes
Type: PE32+ Executable
Architecture: x64
Entry Point: 0x1000
Sections: 4
```

### ✅ Overview Tab
```
DOS HEADER
  Magic: 4d5a (MZ)
  PE Offset: 0x100

NT HEADERS
  Signature: 0x4550 (PE)
  Machine: 0x8664 (x64)
  Number of Sections: 4
```

### ✅ Disassembly Tab
```
Address              Bytes                    Mnemonic     Operands
0x0000000000401000   48 83 ec 28              sub          rsp, 0x28
0x0000000000401004   48 8b 05 d5 2f 00 00     mov          rax, qword ptr [rip + 0x2fd5]
```

### ✅ Hex View Tab
```
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  MZ..............
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......
```

### ✅ Strings Tab
```
0x00001234: PuTTY
0x00001250: SSH Client
0x00001260: Copyright Simon Tatham
```

## Troubleshooting

### "No file loaded" error
- Make sure you selected a valid .exe file
- Verify the file is Windows PE format: `file your_file.exe`
- Check the file isn't corrupted

### "Failed to parse PE" error
- The file might not be a valid PE executable
- Try a different .exe file
- Use the PuTTY download (guaranteed to work)

## Step-by-Step for Complete Beginners

1. **Download PuTTY:**
```bash
curl -L "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe" -o ~/Downloads/putty.exe
```

2. **Start EXE Analyzer:**
```bash
cd ~/Developer/analyse/exe_analyzer
python main.py
```

3. **In the window that opens:**
   - Click the "📁 Open" button (top left)
   - A file dialog will appear
   - Navigate to your Downloads folder
   - Click on "putty.exe"
   - Click "Open"

4. **Watch the magic happen:**
   - Progress bar will show analysis progress
   - File info will appear on the left
   - Click different tabs to see analysis results

## Alternative: If You Have Windows Access

If you have access to a Windows computer:

1. Copy any .exe file:
   - `C:\Windows\System32\notepad.exe`
   - `C:\Windows\System32\calc.exe`
   - Any program you want to analyze

2. Transfer to your Mac via:
   - USB drive
   - Email attachment
   - Cloud storage (Dropbox, Google Drive)
   - AirDrop (if recent Windows/Mac)

3. Analyze it!

---

**TL;DR - Run these 3 commands:**

```bash
# 1. Download test file
curl -L "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe" -o ~/Downloads/putty.exe

# 2. Start analyzer
cd ~/Developer/analyse/exe_analyzer && python main.py

# 3. In the GUI: Click "Open" → select putty.exe → Enjoy!
```

**You're ready to analyze executables!** 🎉
