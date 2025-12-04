# How to Get Test .EXE Files for EXE Analyzer

## ⚠️ Important Note

The EXE Analyzer is designed for **Windows PE files** (.exe, .dll).

You are currently on **macOS**, which uses Mach-O format executables, not PE format.

## 📦 Options to Get Windows .EXE Files

### Option 1: Download Safe Test Samples ✅ **RECOMMENDED**

Download legitimate, safe Windows executables from official sources:

#### A. Windows System Files (If you have access to Windows)
```
C:\Windows\System32\notepad.exe
C:\Windows\System32\calc.exe
C:\Windows\System32\cmd.exe
```

Transfer these files to macOS using:
- USB drive
- Cloud storage (Dropbox, Google Drive)
- Network share
- Email

#### B. Download Open Source Windows Programs

**Safe sources:**
1. **Notepad++** - https://notepad-plus-plus.org/downloads/
2. **7-Zip** - https://www.7-zip.org/download.html
3. **PuTTY** - https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
4. **WinSCP** - https://winscp.net/eng/download.php

### Option 2: Use Sample PE Files from GitHub

Many security researchers share sample PE files:

```bash
# Example: Download a simple PE sample
curl -L https://github.com/corkami/pocs/raw/master/PE/tiny.exe -o tiny.exe
```

**Warning:** Only download from trusted sources!

### Option 3: Create Windows .EXE on Windows

If you have access to a Windows machine or Windows VM:

**Method A: Using Python + PyInstaller**
```bash
# On Windows:
pip install pyinstaller
pyinstaller --onefile test_program.py
# Result: dist/test_program.exe
```

**Method B: Using MinGW (C compiler)**
```bash
# On Windows with MinGW:
gcc test_program.c -o test_program.exe
```

### Option 4: Cross-Compile on macOS (Advanced)

Install MinGW cross-compiler to create Windows executables from macOS:

```bash
# Install mingw-w64
brew install mingw-w64

# Compile for Windows
x86_64-w64-mingw32-gcc test_program.c -o test_program.exe

# Or for 32-bit
i686-w64-mingw32-gcc test_program.c -o test_program32.exe
```

### Option 5: Use Windows in Virtual Machine

1. Install VirtualBox or VMware
2. Create Windows VM
3. Create .exe files in the VM
4. Copy files to macOS

## 🧪 Quick Test with MinGW (Try This!)

Let me try to install MinGW and create a Windows .exe for you:

```bash
# Install MinGW cross-compiler
brew install mingw-w64

# Compile the test program for Windows
cd /Users/javad/Developer/analyse
x86_64-w64-mingw32-gcc test_program.c -o test_program.exe

# Now you have a Windows .exe file!
```

## 📁 Where I Created Test Files

I've already created:
1. **test_program.c** - Simple C program (source code)
2. **test_program.py** - Simple Python program (source code)
3. **dist/test_app** - macOS executable (Mach-O format - won't work with EXE Analyzer)

## 🔍 How to Verify You Have a PE File

Before analyzing, check the file type:

```bash
file your_file.exe
```

**Good output (Windows PE):**
```
your_file.exe: PE32+ executable (console) x86-64, for MS Windows
```

**Wrong output (macOS):**
```
your_file: Mach-O 64-bit executable arm64
```

## ✅ Recommended Steps for You

### Step 1: Install MinGW
```bash
brew install mingw-w64
```

### Step 2: Compile Test Program
```bash
cd /Users/javad/Developer/analyse
x86_64-w64-mingw32-gcc test_program.c -o test_program.exe
```

### Step 3: Analyze with EXE Analyzer
```bash
cd exe_analyzer
python main.py
# Then open test_program.exe
```

## 🎯 What You'll See in EXE Analyzer

When you analyze a Windows .exe file, you'll see:

### File Information Panel
- File type: PE32 or PE32+
- Architecture: x86 or x64
- Entry point address
- Number of sections

### Overview Tab
- DOS Header (MZ signature)
- NT Headers (PE signature)
- Optional Header details
- Data Directories

### Disassembly Tab
```
Address              Bytes                    Mnemonic     Operands
0x0000000000401000   55                       push         rbp
0x0000000000401001   48 89 e5                 mov          rbp, rsp
```

### Hex View Tab
```
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  MZ..............
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......
```

### Strings Tab
```
0x00001234: Test Application
0x00001250: Version: 1.0.0
0x00001260: Hello, World!
```

### Imports/Exports Tab
```
DLL: kernel32.dll
  - GetStdHandle
  - WriteConsoleA
  - ExitProcess
```

### Sections Tab
```
Name       VirtAddr     VirtSize     RawSize      Entropy    Flags
.text      0x00001000   0x00002000   0x00002000   5.234      CODE|EXEC|READ
.data      0x00003000   0x00001000   0x00001000   3.456      DATA|READ|WRITE
.rdata     0x00004000   0x00001000   0x00001000   4.123      DATA|READ
```

## 🔒 Safety Reminders

1. **Never analyze unknown .exe files on your main system**
2. **Use virtual machines for suspicious files**
3. **Only download from trusted sources**
4. **The EXE Analyzer performs static analysis only (safe)**

## 📞 Need Help?

If you have questions about:
- Getting Windows .exe files
- Using the analyzer
- Understanding results

Check the documentation:
- **README.md** - Feature overview
- **USAGE.md** - Detailed usage guide
- **QUICKSTART.md** - Quick start guide

## 🎉 Summary

**You are on macOS, so:**
1. ✅ Install mingw-w64: `brew install mingw-w64`
2. ✅ Compile test program: `x86_64-w64-mingw32-gcc test_program.c -o test_program.exe`
3. ✅ Run analyzer: `python main.py`
4. ✅ Open the .exe file

**Or:**
- Download Windows programs from official websites
- Copy files from a Windows machine
- Use Windows in a VM

---

**Ready to analyze Windows executables!** 🔍
