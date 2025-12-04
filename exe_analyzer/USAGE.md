# EXE Analyzer - Usage Guide

## Quick Start

### 1. Installation

**Linux/Mac:**
```bash
chmod +x setup.sh
./setup.sh
```

**Windows:**
```batch
setup.bat
```

**Manual:**
```bash
pip install -r requirements.txt
```

### 2. Launch Application

```bash
python main.py
```

## Step-by-Step Tutorial

### Opening a File

1. Click the **"📁 Open"** button in the toolbar
2. Or use menu: **File → Open EXE/DLL**
3. Or press **Ctrl+O**
4. Select an executable file (.exe or .dll)
5. Wait for initial analysis (progress bar shows status)

### Understanding the Interface

#### Left Panel - File Information
Shows basic file properties:
- File name and path
- File size
- Architecture (x86/x64)
- Entry point address
- Number of sections

#### Main Panel - Tabbed Views

**Overview Tab:**
- DOS Header details
- NT Headers (File Header, Optional Header)
- Data Directories
- Complete PE structure breakdown

**Disassembly Tab:**
- Assembly code from entry point
- Disassembly of .text section
- Memory addresses and opcodes
- Instructions with operands

**Hex View Tab:**
- Raw binary data in hexadecimal
- ASCII representation
- Addresses and offsets

**Strings Tab:**
- All extracted strings
- Offset in file
- Minimum length filtering

**Imports/Exports Tab:**
- Imported DLLs and functions
- Exported functions (for DLLs)
- Addresses and ordinals

**Sections Tab:**
- Section names (.text, .data, .rdata, etc.)
- Virtual addresses and sizes
- Entropy values
- Permissions (READ, WRITE, EXEC)

## Common Operations

### 1. Analyzing PE Structure

**Steps:**
1. Open a file
2. Click **"🔍 Analyze"** button or use **Analysis → Analyze PE Structure**
3. Wait for analysis to complete
4. View results in **Sections** tab

**What it shows:**
- All section headers
- Section characteristics
- Entropy analysis (detects encryption/packing)
- Memory layout

### 2. Disassembling Code

**Steps:**
1. Open a file
2. Click **"⚙️ Disassemble"** button or use **Analysis → Disassemble Code**
3. Wait for disassembly (may take a moment)
4. View results in **Disassembly** tab

**Output format:**
```
Address              Bytes                    Mnemonic     Operands
0x0000000000401000   55                       push         rbp
0x0000000000401001   48 89 e5                 mov          rbp, rsp
0x0000000000401004   48 83 ec 20              sub          rsp, 0x20
```

### 3. Extracting Strings

**Steps:**
1. Open a file
2. Click **"🔤 Strings"** button or use **Analysis → Extract Strings**
3. View results in **Strings** tab

**Use cases:**
- Find hardcoded paths
- Discover error messages
- Identify URLs and domains
- Look for suspicious strings

### 4. Viewing Hex Dump

**Steps:**
1. Open a file
2. Click **"📊 Hex View"** button or use **View → Hex View**
3. Scroll through raw bytes

**Format:**
```
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  MZ..............
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......
```

### 5. Analyzing Imports

**Steps:**
1. Open a file
2. Use **Analysis → Find Imports/Exports**
3. View in **Imports/Exports** tab

**Look for:**
- Suspicious APIs (CreateRemoteThread, VirtualAllocEx)
- Network functions (socket, connect, send)
- File operations (CreateFile, WriteFile)
- Registry access (RegOpenKey, RegSetValue)

### 6. Detecting Packers

**Steps:**
1. Open a file
2. Use **Analysis → Detect Packer/Obfuscation**
3. View detection results

**Indicators:**
- Known packer signatures (UPX, PECompact, etc.)
- High entropy (>7.0)
- Suspicious section names
- Unusual entry point

### 7. Calculating Entropy

**Steps:**
1. Open a file
2. Use **Tools → Calculate Entropy**
3. View entropy value

**Interpretation:**
- < 5.0: Normal, unencrypted
- 5.0 - 7.0: Compressed or structured
- > 7.0: Likely encrypted or packed

### 8. Searching for Strings

**Steps:**
1. Open a file
2. Use **Tools → String Search**
3. Enter search term
4. View results

**Examples:**
- Search for "password"
- Search for "http://"
- Search for specific function names

## Exporting Results

### Export Disassembly

**Steps:**
1. Disassemble the file first
2. Use **File → Export Disassembly**
3. Choose location and filename
4. Save as .asm or .txt

**Use cases:**
- Share analysis results
- Compare with other tools
- Create documentation

### Export Hex Dump

**Steps:**
1. Open file and view hex
2. Use **File → Export Hex Dump**
3. Save to file

## Advanced Usage

### Analyzing Malware (Safely)

⚠️ **Always analyze malware in an isolated environment!**

**Best practices:**
1. Use a virtual machine
2. Disable network access
3. Take VM snapshots before analysis
4. Never execute the malware

**Analysis workflow:**
1. Open malware in EXE Analyzer
2. Check file information (architecture, compiler)
3. Calculate entropy (check for packing)
4. Extract strings (look for IOCs)
5. Analyze imports (identify capabilities)
6. Review disassembly (understand behavior)
7. Document findings

### Analyzing .NET Files

**Steps:**
1. Use **File → Open .NET Assembly**
2. View PE structure (still works)
3. Check for .NET metadata

**Note:** Full .NET decompilation requires additional tools like dnSpy or ILSpy.

### Comparing Two Files

**Coming soon:** File comparison feature

**Manual comparison:**
1. Open first file, export disassembly
2. Open second file, export disassembly
3. Use diff tool to compare

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+O | Open file |
| Ctrl+S | Export disassembly |

## Tips & Tricks

### 1. Quick File Check
- Check entropy first to detect packing
- If entropy > 7.0, file is likely packed (try unpacking first)

### 2. Finding Entry Point
- Look at "Entry Point" in File Information panel
- This is where execution starts

### 3. Identifying File Type
- Check status bar for file type
- .NET files show ".NET Assembly"
- Native files show "PE32 Executable"

### 4. Understanding Sections

**Common sections:**
- `.text`: Code
- `.data`: Initialized data
- `.rdata`: Read-only data (strings, constants)
- `.bss`: Uninitialized data
- `.rsrc`: Resources (icons, dialogs)

### 5. Suspicious Indicators

**Red flags:**
- High entropy (>7.5)
- Unusual section names (.aspack, .themida)
- Empty import table
- Large .rsrc section
- Mismatched timestamp
- Many WRITE+EXEC sections

### 6. Performance Tips
- Large files (>50MB) may take time to disassemble
- Disassembly is limited to first 500 instructions per section
- Use string search instead of browsing all strings

## Troubleshooting

### Problem: "Failed to parse PE"
**Solution:**
- Ensure file is a valid PE executable
- Check file is not corrupted
- Try a different file

### Problem: Disassembly shows "Unsupported architecture"
**Solution:**
- Check file architecture in File Information
- Tool supports x86 and x64 only
- ARM support is limited

### Problem: "Capstone not installed"
**Solution:**
```bash
pip install capstone --upgrade
```

### Problem: Slow performance
**Solution:**
- Close other applications
- Analyze smaller sections
- Use string search instead of full extraction

### Problem: Can't see all strings
**Solution:**
- Output is limited to 500 strings
- Use string search to find specific strings
- Export to file for full list

## Example Analysis Workflow

### Scenario: Unknown Executable

1. **Initial Triage**
   ```
   - Open file
   - Check file size and type
   - Note entry point address
   ```

2. **Quick Checks**
   ```
   - Calculate entropy
   - Check for packer signatures
   - Look at section names
   ```

3. **String Analysis**
   ```
   - Extract all strings
   - Search for URLs, IPs
   - Look for error messages
   - Find file paths
   ```

4. **Import Analysis**
   ```
   - Review imported DLLs
   - Check for suspicious APIs:
     * Network: ws2_32.dll, wininet.dll
     * Process: kernel32.dll (CreateProcess, VirtualAlloc)
     * Crypto: advapi32.dll (CryptEncrypt)
   ```

5. **Code Analysis**
   ```
   - Disassemble entry point
   - Look for anti-analysis techniques
   - Identify main functionality
   ```

6. **Documentation**
   ```
   - Export disassembly
   - Save string list
   - Document findings
   ```

## Getting Help

- Read README.md for feature overview
- Check this USAGE.md for detailed instructions
- Review error messages carefully
- Ensure all dependencies are installed

## Best Practices

1. **Always analyze unknown files in a VM**
2. **Take notes during analysis**
3. **Export important findings**
4. **Compare with other tools**
5. **Never execute suspicious files**
6. **Keep tools updated**
7. **Use multiple analysis methods**

## Next Steps

After mastering EXE Analyzer, consider learning:
- **x64dbg**: Dynamic analysis and debugging
- **IDA Pro**: Professional disassembler
- **Ghidra**: Advanced reverse engineering
- **PE-bear**: PE structure visualization
- **dnSpy**: .NET decompiler

---

**Happy Analyzing! 🔍**
