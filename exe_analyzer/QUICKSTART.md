# Quick Start Guide - EXE Analyzer

Get started in 3 minutes! ⚡

## 🚀 Installation (30 seconds)

### Linux / Mac
```bash
cd exe_analyzer
./setup.sh
```

### Windows
```batch
cd exe_analyzer
setup.bat
```

### Manual
```bash
pip install pefile capstone dnfile
```

## ✅ Verify Installation (10 seconds)

```bash
python test_installation.py
```

You should see all ✓ checkmarks.

## 🎮 Launch Application (5 seconds)

```bash
python main.py
```

Or use the quick launch script:
```bash
./run.sh
```

## 📖 First Analysis (2 minutes)

### Step 1: Open a File
- Click **"📁 Open"** button
- Select any .exe or .dll file
- Wait for analysis (progress bar shows status)

### Step 2: View Information
Check the tabs:
- **Overview** - PE structure
- **Disassembly** - Assembly code
- **Hex View** - Raw bytes
- **Strings** - Extracted text
- **Imports/Exports** - External functions
- **Sections** - Memory sections

### Step 3: Perform Analysis

Click toolbar buttons:
- **🔍 Analyze** - Full PE analysis
- **⚙️ Disassemble** - Disassemble code
- **🔤 Strings** - Extract strings
- **📊 Hex View** - View hex dump

### Step 4: Export Results
- File → Export Disassembly
- File → Export Hex Dump

## 🎯 Try These Files

### Safe Test Files
- `C:\Windows\System32\notepad.exe` (Windows)
- `/bin/ls` (Linux - use with PE files)
- Any program you wrote

### ⚠️ Safety Warning
**Never analyze unknown files on your main system!**
- Use virtual machines for suspicious files
- Disable network when analyzing malware
- Analysis only - never execute suspicious files

## 💡 Quick Tips

1. **High Entropy?** File might be packed → Use Analysis → Detect Packer
2. **Suspicious APIs?** Check Imports/Exports tab
3. **Find Strings?** Use Tools → String Search
4. **Need Help?** Read USAGE.md for detailed guide

## 📚 Next Steps

1. Read **README.md** - Complete feature list
2. Read **USAGE.md** - Detailed instructions
3. Read **PROJECT_SUMMARY.md** - Technical details

## ⌨️ Keyboard Shortcuts

- `Ctrl+O` - Open file
- `Ctrl+S` - Export disassembly

## 🆘 Troubleshooting

### "Module not found" error
```bash
pip install -r requirements.txt
```

### "Failed to parse PE"
- Ensure file is a Windows executable
- Check file is not corrupted

### GUI doesn't start
- Ensure tkinter is installed (built-in with Python)
- Try: `python -m tkinter` to test

## ✨ You're Ready!

That's it! You now have a professional binary analysis tool.

**Start analyzing executables now!** 🔍

---

For detailed instructions, see **USAGE.md**
