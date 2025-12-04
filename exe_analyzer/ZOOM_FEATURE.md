# Zoom Feature - EXE Analyzer

## ✨ NEW FEATURE: Text Size Zoom

The EXE Analyzer now includes comprehensive zoom functionality to adjust text size across all views!

## 🎯 How to Use Zoom

### Method 1: Toolbar Buttons (Quickest)

Look at the toolbar - you'll see:
```
[📁 Open] [🔍 Analyze] [⚙️ Disassemble] [🔤 Strings] [📊 Hex View] | [🔍+] [🔍-] [100%]
```

- **🔍+ Button** - Zoom in (increase text size)
- **🔍- Button** - Zoom out (decrease text size)
- **Green "100%" Label** - Shows current zoom level

**Steps:**
1. Click **🔍+** to make text bigger
2. Click **🔍-** to make text smaller
3. Watch the percentage update in real-time

### Method 2: Keyboard Shortcuts (Fastest)

| Shortcut | Action |
|----------|--------|
| **Ctrl + Plus (+)** | Zoom in (increase by 10%) |
| **Ctrl + Minus (-)** | Zoom out (decrease by 10%) |
| **Ctrl + 0** | Reset to 100% (default) |

**Tips:**
- Press **Ctrl+=** also works for zoom in (no shift needed)
- Hold Ctrl and press + multiple times for bigger text
- Hold Ctrl and press - multiple times for smaller text

### Method 3: View Menu (Most Options)

1. Click **View** menu in menu bar
2. Click **Zoom** submenu
3. Choose from:
   - **Zoom In** (Ctrl++)
   - **Zoom Out** (Ctrl+-)
   - **Reset Zoom** (Ctrl+0)
   - ─────────────
   - **50%** (very small)
   - **75%** (small)
   - **100% (Default)** (normal)
   - **125%** (large)
   - **150%** (larger)
   - **200%** (very large)

## 📊 Zoom Levels Explained

| Level | Description | When to Use |
|-------|-------------|-------------|
| **50%** | Very small | Fit more content, overview mode |
| **75%** | Small | See more code at once |
| **100%** | Default | Normal size, best balance |
| **125%** | Large | Easier reading |
| **150%** | Larger | High-resolution displays |
| **200%** | Very large | Presentations, accessibility |
| **300%** | Maximum | Maximum zoom (automatic limit) |

## ✅ What Gets Zoomed

Zoom affects **ALL text views**:
- ✅ File Information panel (left panel)
- ✅ Overview tab
- ✅ Disassembly tab
- ✅ Hex View tab
- ✅ Strings tab
- ✅ Imports/Exports tab
- ✅ Sections tab

## 🎨 Visual Feedback

When you change zoom:
1. **Toolbar label updates**: Shows current percentage (e.g., "125%")
2. **Status bar updates**: Shows "Zoom level: 125%"
3. **All text resizes**: Immediately applies to all views
4. **Color remains**: Green label shows zoom is active

## 📝 Examples

### Example 1: Make Text Bigger for Presentations
```
1. Open EXE Analyzer
2. Load putty.exe
3. Press Ctrl++ three times
4. Zoom is now 130% (larger text)
5. Perfect for presentations!
```

### Example 2: Fit More Code on Screen
```
1. Open disassembly view
2. Press Ctrl+- twice
3. Zoom is now 80% (smaller text)
4. See more instructions at once
```

### Example 3: High-DPI Display Adjustment
```
1. Open application
2. View → Zoom → 150%
3. Text is now crisp and readable on 4K displays
```

### Example 4: Quick Reset
```
1. Zoom is at 175% (too big)
2. Press Ctrl+0
3. Instantly back to 100% default
```

## 🔧 Technical Details

### Font Scaling
- Base font: Courier (monospace for code)
- File Info: 9pt base → scales 4.5pt to 27pt
- Overview/Disasm: 10pt base → scales 5pt to 30pt
- Hex/Strings: 9pt base → scales 4.5pt to 27pt

### Zoom Range
- **Minimum**: 50% (text too small below this)
- **Maximum**: 300% (text too large above this)
- **Step**: 10% per click or keyboard press
- **Default**: 100% (normal size)

### Performance
- Instant resize: No lag or delay
- All views update simultaneously
- Zoom level persists during session
- Reset when application restarts

## 🎯 Use Cases

### For Developers
- **Debugging**: Zoom in to see assembly details
- **Code Review**: Zoom out to see more context
- **Comparing**: Adjust size to match other tools

### For Security Researchers
- **Analysis**: Zoom in to examine hex bytes carefully
- **Screenshots**: Zoom to appropriate size for reports
- **Presentations**: Large text for demos

### For Students
- **Learning**: Bigger text for easier reading
- **Note Taking**: Zoom out to capture more in screenshots
- **Studying**: Adjust for comfort during long sessions

### For Accessibility
- **Visual Impairment**: Large text (150-200%)
- **High-DPI Displays**: Adjust for screen resolution
- **Low Vision**: Maximum zoom (300%)

## 💡 Tips & Tricks

### Tip 1: Find Your Sweet Spot
Try different zoom levels to find what works best for your screen:
- **Laptop (13-15")**: Try 110-125%
- **Desktop (24")**: Try 100-110%
- **4K Display**: Try 150-175%

### Tip 2: Zoom Before Analyzing
Set your preferred zoom level right after opening the application, before loading a file.

### Tip 3: Different Zoom for Different Tasks
- **Disassembly**: 100-110% (need to see mnemonics clearly)
- **Hex View**: 90-100% (more bytes visible)
- **Strings**: 100-125% (easier reading)

### Tip 4: Presentation Mode
For demos or teaching:
```
1. Press Ctrl++ multiple times
2. Aim for 150-200%
3. Everyone can see clearly!
```

### Tip 5: Quick Toggle
```
Ctrl+0  → Reset to 100%
Ctrl++  → Zoom to 110% (your preference)
Ctrl+0  → Back to 100%
```

## ⌨️ Keyboard Shortcuts Reference

```
╔═══════════════╦══════════════════╗
║   Shortcut    ║      Action      ║
╠═══════════════╬══════════════════╣
║  Ctrl + +     ║  Zoom In (+10%)  ║
║  Ctrl + =     ║  Zoom In (+10%)  ║
║  Ctrl + -     ║  Zoom Out (-10%) ║
║  Ctrl + 0     ║  Reset to 100%   ║
╚═══════════════╩══════════════════╝
```

## 🐛 Troubleshooting

### Text is too small to read
**Solution**: Press Ctrl++ several times, or View → Zoom → 150%

### Text is too large
**Solution**: Press Ctrl+- several times, or View → Zoom → 75%

### Zoom level stuck
**Solution**: Press Ctrl+0 to reset to 100%

### Zoom label shows but text doesn't change
**Solution**:
1. Close the application
2. Restart: `python main.py`
3. Zoom should work properly

### Text looks blurry at high zoom
**Normal behavior**: Very high zoom (>200%) may look pixelated on some displays.

## 📸 Visual Guide

### Before Zoom (100%)
```
Address              Bytes      Mnemonic
0x0000000000401000   48 83 ec   sub rsp, 0x28
```

### After Zoom In (150%)
```
Address              Bytes      Mnemonic
0x0000000000401000   48 83 ec   sub rsp, 0x28
(Text appears 50% larger)
```

### After Zoom Out (75%)
```
Address              Bytes      Mnemonic
0x0000000000401000   48 83 ec   sub rsp, 0x28
(Text appears 25% smaller, more content visible)
```

## 🎉 Quick Start

**Try it now:**

1. **Open the application** (if not already running)
   ```bash
   cd exe_analyzer
   python main.py
   ```

2. **Test zoom:**
   - Press **Ctrl++** (text gets bigger)
   - Press **Ctrl+-** (text gets smaller)
   - Press **Ctrl+0** (back to normal)

3. **Use toolbar:**
   - Click **🔍+** button (zoom in)
   - Click **🔍-** button (zoom out)
   - Watch the **green percentage** update

4. **Try View menu:**
   - Click **View → Zoom → 150%**
   - See all text resize immediately!

---

## ✨ Summary

**Zoom is now available in 3 ways:**
1. 🖱️ **Toolbar buttons**: Click 🔍+ or 🔍-
2. ⌨️ **Keyboard**: Ctrl++, Ctrl+-, Ctrl+0
3. 📋 **Menu**: View → Zoom → (choose percentage)

**All text views resize together!**

**Enjoy your customized viewing experience!** 🔍✨

---

*Feature added: November 2025*
*Compatible with: EXE Analyzer v1.0+*
