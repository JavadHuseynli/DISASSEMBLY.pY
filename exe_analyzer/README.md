# EXE Analyzer - Visual Binary Disassembler & Reverse Engineering Tool

A comprehensive Python-based tool for analyzing, disassembling, and reverse engineering Windows executable files (.exe, .dll) with a modern graphical user interface.

## ⚠️ LEGAL NOTICE

This tool is designed for **legitimate security research, malware analysis, and educational purposes only**.

- Only use on files you have authorization to analyze
- Do not use for illegal reverse engineering or software piracy
- Respect software licenses and intellectual property rights
- Use responsibly for defensive security research

## 🎯 Features

### Core Functionality
- **PE File Analysis**: Complete parsing of Portable Executable (PE) file structure
- **x86/x64 Disassembly**: Powerful disassembly engine using Capstone
- **Hex Viewer**: View raw binary data in hex format
- **String Extraction**: Extract ASCII and Unicode strings from binaries
- **Import/Export Analysis**: View imported and exported functions
- **.NET Support**: Basic analysis of .NET assemblies
- **Section Analysis**: Detailed section information with entropy calculation
- **Packer Detection**: Detect common packers and obfuscation

### Visual Interface
- **Modern GUI**: Dark-themed professional interface
- **Menu Bar**: Complete menu system with shortcuts
- **Toolbar**: Quick access buttons for common operations
- **Progress Bars**: Visual feedback for long operations
- **Tabbed Views**: Multiple views in organized tabs
- **Syntax Highlighting**: Color-coded disassembly output

### Analysis Capabilities

#### 1. PE Structure Analysis
- DOS Header
- NT Headers (File Header, Optional Header)
- Data Directories
- Section Headers
- Import/Export Tables
- Resource Information

#### 2. Code Analysis
- Disassembly from entry point
- Section-by-section disassembly
- Opcode visualization
- Memory address mapping

#### 3. Binary Analysis
- Hex dump viewer
- Entropy calculation (file and per-section)
- Byte pattern searching
- String searching

#### 4. Security Analysis
- Packer/obfuscation detection
- Entropy analysis for encryption detection
- Import analysis for suspicious APIs
- Section characteristics analysis

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
# Navigate to project directory
cd exe_analyzer

# Install required packages
pip install -r requirements.txt
```

### Manual Installation

```bash
pip install pefile>=2023.2.7
pip install capstone>=5.0.1
pip install dnfile>=0.14.1
```

## 🚀 Usage

### Starting the Application

```bash
python main.py
```

### Basic Workflow

1. **Open File**
   - Click "📁 Open" button or use `Ctrl+O`
   - Select an .exe or .dll file
   - Wait for initial analysis to complete

2. **View Information**
   - Check the left panel for basic file information
   - View the Overview tab for detailed PE structure
   - Browse different tabs for specific analysis

3. **Perform Analysis**
   - Click "🔍 Analyze" to perform full PE structure analysis
   - Click "⚙️ Disassemble" to disassemble the code
   - Click "🔤 Strings" to extract strings
   - Click "📊 Hex View" to view raw bytes

4. **Export Results**
   - Use File menu → Export Disassembly
   - Use File menu → Export Hex Dump

### Menu Options

#### File Menu
- **Open EXE/DLL**: Open Windows executables
- **Open .NET Assembly**: Open .NET files
- **Export Disassembly**: Save disassembly to .asm file
- **Export Hex Dump**: Save hex dump to file

#### Analysis Menu
- **Analyze PE Structure**: Detailed PE analysis
- **Disassemble Code**: Generate disassembly
- **Extract Strings**: Find all strings
- **Find Imports/Exports**: Show imported/exported functions
- **Detect Packer/Obfuscation**: Check for packers

#### View Menu
- **Hex View**: Switch to hex viewer
- **Disassembly View**: Switch to disassembly
- **Structure View**: View PE structure
- **Toggle Options**: Show/hide opcodes and comments

#### Tools Menu
- **String Search**: Search for specific strings
- **Byte Pattern Search**: Find byte patterns
- **Calculate Entropy**: Analyze file entropy
- **Compare Files**: Compare two executables

## 📊 Understanding the Output

### Entropy Values
- **0.0 - 1.0**: Empty or uniform data
- **1.0 - 5.0**: Normal code/data
- **5.0 - 7.0**: Compressed or structured data
- **7.0 - 8.0**: High entropy (possibly encrypted/packed)

### Section Flags
- **CODE**: Contains executable code
- **DATA**: Contains initialized data
- **EXEC**: Executable permission
- **READ**: Readable
- **WRITE**: Writable

### Disassembly Format
```
Address              Bytes                    Mnemonic     Operands
0x0000000000401000   55                       push         rbp
0x0000000000401001   48 89 e5                 mov          rbp, rsp
```

## 🔧 Technical Details

### Architecture Support
- x86 (32-bit)
- x86-64 (64-bit)
- ARM (basic support)

### File Format Support
- PE32 (32-bit executables)
- PE32+ (64-bit executables)
- DLL files
- .NET assemblies (basic)

### Disassembly Engine
Uses Capstone disassembly framework:
- Fast and accurate disassembly
- Multiple architecture support
- Instruction-level details

## 📁 Project Structure

```
exe_analyzer/
│
├── main.py              # Main GUI application
├── analyzer_core.py     # Core analysis engine
├── ui_components.py     # UI components and widgets
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## 🛠️ Advanced Features

### String Extraction
Extracts both ASCII and Unicode strings with configurable minimum length:
- Shows offset in file
- Filters printable characters
- Displays up to 500 strings

### Import Analysis
Shows all imported DLLs and functions:
- Identifies suspicious APIs
- Shows import by name or ordinal
- Useful for behavioral analysis

### Entropy Analysis
Calculates Shannon entropy:
- File-level entropy
- Per-section entropy
- Helps detect encryption/packing

### Packer Detection
Detects common packers:
- UPX
- PECompact
- ASPack
- Themida
- VMProtect

## 🎨 UI Features

### Color Scheme
- Dark theme for reduced eye strain
- Syntax highlighting for disassembly
- Color-coded information types

### Progress Indicators
- Real-time progress bars
- Status updates
- Operation feedback

### Keyboard Shortcuts
- `Ctrl+O`: Open file
- `Ctrl+S`: Export disassembly

## 🔍 Use Cases

### Malware Analysis
- Analyze suspicious executables safely
- Identify malicious behaviors
- Extract indicators of compromise (IOCs)

### Software Security
- Audit software binaries
- Find security vulnerabilities
- Analyze binary protections

### Reverse Engineering
- Understand program structure
- Analyze algorithms
- Study file formats

### Education
- Learn about PE file format
- Study assembly language
- Understand binary analysis

## ⚡ Performance

- Fast loading of files up to 100MB
- Efficient disassembly with caching
- Multi-threaded analysis
- Progressive rendering for large outputs

## 🐛 Troubleshooting

### Capstone Not Found
```bash
pip install capstone --upgrade
```

### PE File Parse Error
- Ensure file is a valid PE executable
- Check file is not corrupted
- Try opening as .NET assembly

### Disassembly Fails
- Verify architecture is supported
- Check if file is packed (try unpacking first)
- Ensure entry point is valid

## 🔄 Future Enhancements

- [ ] Advanced .NET decompilation (IL code)
- [ ] Plugin system for extensibility
- [ ] Binary patching capabilities
- [ ] Graphical flow charts
- [ ] Cross-references (xrefs)
- [ ] Function identification
- [ ] Signature scanning (YARA)
- [ ] Debugger integration
- [ ] Cloud-based analysis
- [ ] Compare multiple files side-by-side

## 📚 Resources

### Learn More
- **PE Format**: [Microsoft PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- **Capstone**: [Capstone Disassembly Framework](https://www.capstone-engine.org/)
- **Malware Analysis**: Study reverse engineering techniques

### Related Tools
- **IDA Pro**: Professional disassembler
- **Ghidra**: NSA's reverse engineering suite
- **x64dbg**: Windows debugger
- **PE Explorer**: PE file viewer
- **dnSpy**: .NET debugger and decompiler

## 👨‍💻 Contributing

This is an educational tool. Contributions welcome:
- Bug fixes
- Feature additions
- Documentation improvements
- UI enhancements

## 📄 License

This tool is provided for educational and security research purposes.

## 🙏 Credits

Built with:
- **pefile**: Excellent PE parsing library
- **Capstone**: Powerful disassembly engine
- **dnfile**: .NET file parsing
- **Python & Tkinter**: GUI framework

## ⚠️ Disclaimer

This tool is provided "as is" without warranty. The authors are not responsible for:
- Misuse of the tool
- Damage caused by analyzing malicious files
- Legal issues arising from unauthorized reverse engineering

**Always analyze unknown files in a safe, isolated environment (sandbox/VM).**

## 📞 Support

For issues, questions, or suggestions:
- Check documentation first
- Review error messages carefully
- Ensure all dependencies are installed
- Test with known-good PE files

---

**Remember**: Use this tool responsibly and ethically. Only analyze files you have authorization to examine.

**Happy Analyzing! 🔍🖥️**
