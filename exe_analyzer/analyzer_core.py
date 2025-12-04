"""
Core analysis engine for EXE Analyzer
Handles PE parsing, disassembly, and binary analysis
"""

import pefile
import struct
import math
from collections import Counter


class ExeAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None
        self.data = None
        self.is_dotnet = False

        # Cross-reference database
        self.xrefs = {}  # address -> {calls_to: [], called_from: [], data_refs: []}
        self.functions = {}  # address -> function info
        self.instructions = {}  # address -> instruction info

        # Load file data
        with open(file_path, 'rb') as f:
            self.data = f.read()

    def parse_pe(self):
        """Parse PE file structure"""
        try:
            self.pe = pefile.PE(self.file_path)

            # Check if .NET
            if hasattr(self.pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
                self.is_dotnet = True

            return True
        except Exception as e:
            raise Exception(f"Failed to parse PE: {str(e)}")

    def get_file_type(self):
        """Determine file type"""
        if not self.pe:
            return "Unknown"

        if self.is_dotnet:
            return ".NET Assembly"

        if self.pe.is_exe():
            return "PE32 Executable"
        elif self.pe.is_dll():
            return "PE32 DLL"
        else:
            return "PE File"

    def get_file_info(self):
        """Get basic file information"""
        if not self.pe:
            return "No file loaded"

        info = []
        info.append("=" * 40)
        info.append("FILE INFORMATION")
        info.append("=" * 40)
        info.append(f"File: {self.file_path.split('/')[-1]}")
        info.append(f"Size: {len(self.data):,} bytes")
        info.append(f"Type: {self.get_file_type()}")
        info.append("")

        # Machine type
        machine = self.pe.FILE_HEADER.Machine
        machine_types = {
            0x14c: "x86",
            0x8664: "x64",
            0x1c0: "ARM",
            0xaa64: "ARM64"
        }
        info.append(f"Architecture: {machine_types.get(machine, f'0x{machine:x}')}")

        # Timestamp
        timestamp = self.pe.FILE_HEADER.TimeDateStamp
        info.append(f"Timestamp: {timestamp} (0x{timestamp:x})")

        # Entry point
        entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        info.append(f"Entry Point: 0x{entry_point:x}")

        # Image base
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        info.append(f"Image Base: 0x{image_base:x}")

        # Subsystem
        subsystem = self.pe.OPTIONAL_HEADER.Subsystem
        subsystem_types = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows CUI",
            5: "OS/2 CUI",
            7: "POSIX CUI"
        }
        info.append(f"Subsystem: {subsystem_types.get(subsystem, str(subsystem))}")

        info.append("")
        info.append(f"Sections: {self.pe.FILE_HEADER.NumberOfSections}")
        info.append(f"Characteristics: 0x{self.pe.FILE_HEADER.Characteristics:x}")

        return "\n".join(info)

    def get_overview(self):
        """Generate file overview"""
        if not self.pe:
            return "No file loaded"

        overview = []
        overview.append("=" * 80)
        overview.append("EXECUTABLE ANALYSIS OVERVIEW")
        overview.append("=" * 80)
        overview.append("")

        # DOS Header
        overview.append("[ DOS HEADER ]")
        overview.append(f"  Magic: {self.pe.DOS_HEADER.e_magic:04x} (MZ)")
        overview.append(f"  PE Offset: 0x{self.pe.DOS_HEADER.e_lfanew:x}")
        overview.append("")

        # NT Headers
        overview.append("[ NT HEADERS ]")
        overview.append(f"  Signature: 0x{self.pe.NT_HEADERS.Signature:x} (PE)")
        overview.append("")

        # File Header
        overview.append("[ FILE HEADER ]")
        overview.append(f"  Machine: 0x{self.pe.FILE_HEADER.Machine:x}")
        overview.append(f"  Number of Sections: {self.pe.FILE_HEADER.NumberOfSections}")
        overview.append(f"  Size of Optional Header: {self.pe.FILE_HEADER.SizeOfOptionalHeader}")
        overview.append(f"  Characteristics: 0x{self.pe.FILE_HEADER.Characteristics:x}")
        overview.append("")

        # Optional Header
        overview.append("[ OPTIONAL HEADER ]")
        overview.append(f"  Magic: 0x{self.pe.OPTIONAL_HEADER.Magic:x}")
        overview.append(f"  Entry Point: 0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
        overview.append(f"  Image Base: 0x{self.pe.OPTIONAL_HEADER.ImageBase:x}")
        overview.append(f"  Section Alignment: 0x{self.pe.OPTIONAL_HEADER.SectionAlignment:x}")
        overview.append(f"  File Alignment: 0x{self.pe.OPTIONAL_HEADER.FileAlignment:x}")
        overview.append(f"  Size of Image: 0x{self.pe.OPTIONAL_HEADER.SizeOfImage:x}")
        overview.append(f"  Size of Headers: 0x{self.pe.OPTIONAL_HEADER.SizeOfHeaders:x}")
        overview.append(f"  Checksum: 0x{self.pe.OPTIONAL_HEADER.CheckSum:x}")
        overview.append(f"  Subsystem: {self.pe.OPTIONAL_HEADER.Subsystem}")
        overview.append("")

        # Data Directories
        overview.append("[ DATA DIRECTORIES ]")
        directories = [
            "Export", "Import", "Resource", "Exception", "Security",
            "Base Reloc", "Debug", "Copyright", "Global Ptr", "TLS",
            "Load Config", "Bound Import", "IAT", "Delay Import", "COM Descriptor"
        ]

        for i, name in enumerate(directories):
            if i < len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY):
                dir_entry = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[i]
                if dir_entry.VirtualAddress != 0:
                    overview.append(f"  {name:20s}: RVA=0x{dir_entry.VirtualAddress:08x} Size=0x{dir_entry.Size:08x}")

        return "\n".join(overview)

    def analyze_sections(self):
        """Analyze PE sections"""
        if not self.pe:
            return "No file loaded"

        sections = []
        sections.append("=" * 100)
        sections.append("SECTIONS ANALYSIS")
        sections.append("=" * 100)
        sections.append("")

        sections.append(f"{'Name':<10} {'VirtAddr':<12} {'VirtSize':<12} {'RawSize':<12} {'Entropy':<10} {'Flags'}")
        sections.append("-" * 100)

        for section in self.pe.sections:
            name = section.Name.decode('utf-8').strip('\x00')
            virt_addr = section.VirtualAddress
            virt_size = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            characteristics = section.Characteristics

            # Calculate entropy
            section_data = section.get_data()
            entropy = self._calculate_entropy(section_data)

            # Decode characteristics
            flags = []
            if characteristics & 0x20:  # IMAGE_SCN_CNT_CODE
                flags.append("CODE")
            if characteristics & 0x40:  # IMAGE_SCN_CNT_INITIALIZED_DATA
                flags.append("DATA")
            if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                flags.append("EXEC")
            if characteristics & 0x40000000:  # IMAGE_SCN_MEM_READ
                flags.append("READ")
            if characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                flags.append("WRITE")

            flags_str = "|".join(flags) if flags else "NONE"

            sections.append(f"{name:<10} 0x{virt_addr:08x}   0x{virt_size:08x}   0x{raw_size:08x}   {entropy:6.3f}     {flags_str}")

        sections.append("")
        sections.append("Entropy Guide:")
        sections.append("  0.0 - 1.0: Empty or uniform data")
        sections.append("  1.0 - 5.0: Normal code/data")
        sections.append("  5.0 - 7.0: Compressed or structured data")
        sections.append("  7.0 - 8.0: High entropy (possibly encrypted/packed)")

        return "\n".join(sections)

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0.0

        entropy = 0
        counter = Counter(data)
        length = len(data)

        for count in counter.values():
            p_x = count / length
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)

        return entropy

    def calculate_entropy(self):
        """Calculate entropy of entire file"""
        return self._calculate_entropy(self.data)

    def disassemble(self):
        """Disassemble executable code"""
        if not self.pe:
            return "No file loaded"

        try:
            # Import capstone for disassembly
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
            except ImportError:
                return "Capstone not installed. Install with: pip install capstone"

            # Determine architecture
            if self.pe.FILE_HEADER.Machine == 0x14c:  # x86
                md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif self.pe.FILE_HEADER.Machine == 0x8664:  # x64
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                return "Unsupported architecture"

            # Get entry point
            entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_offset = self.pe.get_offset_from_rva(entry_point)

            # Disassemble from entry point (limit to 1000 instructions)
            code = self.data[entry_offset:entry_offset + 4096]

            disasm = []
            disasm.append("=" * 80)
            disasm.append("DISASSEMBLY (From Entry Point)")
            disasm.append("=" * 80)
            disasm.append(f"Entry Point RVA: 0x{entry_point:x}")
            disasm.append(f"Entry Point Offset: 0x{entry_offset:x}")
            disasm.append("")
            disasm.append(f"{'Address':<18} {'Bytes':<24} {'Mnemonic':<12} {'Operands'}")
            disasm.append("-" * 80)

            count = 0
            for i in md.disasm(code, entry_point):
                if count >= 500:  # Limit output
                    disasm.append("\n[... truncated ...]")
                    break

                # Format bytes
                bytes_str = " ".join([f"{b:02x}" for b in i.bytes])

                disasm.append(f"0x{i.address:016x}  {bytes_str:<24s} {i.mnemonic:<12s} {i.op_str}")
                count += 1

            # Also disassemble .text section
            disasm.append("\n" + "=" * 80)
            disasm.append("DISASSEMBLY (.text section)")
            disasm.append("=" * 80)

            for section in self.pe.sections:
                if b'.text' in section.Name:
                    section_data = section.get_data()[:4096]  # First 4KB
                    rva = section.VirtualAddress

                    count = 0
                    for i in md.disasm(section_data, rva):
                        if count >= 500:
                            disasm.append("\n[... truncated ...]")
                            break

                        bytes_str = " ".join([f"{b:02x}" for b in i.bytes])
                        disasm.append(f"0x{i.address:016x}  {bytes_str:<24s} {i.mnemonic:<12s} {i.op_str}")
                        count += 1
                    break

            return "\n".join(disasm)

        except Exception as e:
            return f"Disassembly error: {str(e)}"

    def extract_strings(self, min_length=4):
        """Extract ASCII and Unicode strings"""
        strings = []
        strings.append("=" * 80)
        strings.append("EXTRACTED STRINGS")
        strings.append("=" * 80)
        strings.append(f"Minimum length: {min_length} characters")
        strings.append("")

        # ASCII strings
        ascii_strings = []
        current_string = []
        offset = 0

        for i, byte in enumerate(self.data):
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    ascii_strings.append((offset, ''.join(current_string)))
                current_string = []
                offset = i + 1

        if len(current_string) >= min_length:
            ascii_strings.append((offset, ''.join(current_string)))

        # Display strings
        strings.append(f"Found {len(ascii_strings)} ASCII strings:\n")

        for offset, s in ascii_strings[:500]:  # Limit to 500 strings
            strings.append(f"0x{offset:08x}: {s}")

        if len(ascii_strings) > 500:
            strings.append(f"\n[... {len(ascii_strings) - 500} more strings ...]")

        return "\n".join(strings)

    def get_imports_exports(self):
        """Get imports and exports"""
        if not self.pe:
            return "No file loaded"

        result = []
        result.append("=" * 80)
        result.append("IMPORTS AND EXPORTS")
        result.append("=" * 80)
        result.append("")

        # Imports
        result.append("[ IMPORTS ]")
        result.append("")

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                result.append(f"DLL: {dll_name}")

                for imp in entry.imports[:50]:  # Limit to 50 per DLL
                    if imp.name:
                        result.append(f"  - {imp.name.decode('utf-8')}")
                    else:
                        result.append(f"  - Ordinal {imp.ordinal}")

                result.append("")
        else:
            result.append("No imports found")

        result.append("")

        # Exports
        result.append("[ EXPORTS ]")
        result.append("")

        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = self.pe.DIRECTORY_ENTRY_EXPORT.symbols
            result.append(f"Total exports: {len(exports)}")
            result.append("")

            for exp in exports[:100]:  # Limit to 100
                if exp.name:
                    result.append(f"0x{exp.address:08x}: {exp.name.decode('utf-8')}")
                else:
                    result.append(f"0x{exp.address:08x}: Ordinal {exp.ordinal}")
        else:
            result.append("No exports found")

        return "\n".join(result)

    def get_hex_dump(self, max_bytes=4096):
        """Generate hex dump"""
        lines = []
        lines.append("=" * 80)
        lines.append("HEX DUMP")
        lines.append("=" * 80)
        lines.append("")

        data_to_dump = self.data[:max_bytes]

        for offset in range(0, len(data_to_dump), 16):
            chunk = data_to_dump[offset:offset + 16]

            # Offset
            hex_line = f"{offset:08x}  "

            # Hex bytes
            hex_bytes = ' '.join([f"{b:02x}" for b in chunk])
            hex_line += f"{hex_bytes:<48}  "

            # ASCII representation
            ascii_repr = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
            hex_line += ascii_repr

            lines.append(hex_line)

        if len(self.data) > max_bytes:
            lines.append(f"\n[... {len(self.data) - max_bytes} more bytes ...]")

        return "\n".join(lines)

    def detect_packer(self):
        """Detect common packers"""
        result = ["Packer Detection Results:\n"]

        # Check for common packer signatures
        packers = {
            b'UPX': 'UPX',
            b'PECompact': 'PECompact',
            b'ASPack': 'ASPack',
            b'Themida': 'Themida',
            b'VMProtect': 'VMProtect'
        }

        found = []
        for signature, name in packers.items():
            if signature in self.data:
                found.append(name)

        if found:
            result.append(f"Possible packers detected: {', '.join(found)}")
        else:
            result.append("No common packer signatures found")

        # Check entropy
        entropy = self.calculate_entropy()
        result.append(f"\nFile entropy: {entropy:.4f}")

        if entropy > 7.0:
            result.append("High entropy detected - file may be packed or encrypted")
        else:
            result.append("Normal entropy - file appears unpacked")

        # Check section entropy
        result.append("\nSection entropy:")
        for section in self.pe.sections:
            name = section.Name.decode('utf-8').strip('\x00')
            section_data = section.get_data()
            section_entropy = self._calculate_entropy(section_data)
            result.append(f"  {name}: {section_entropy:.4f}")

        return "\n".join(result)

    def search_string(self, query):
        """Search for a string in the binary"""
        if not query:
            return "Please enter a search query"

        results = []
        query_bytes = query.encode('utf-8')

        offset = 0
        while True:
            offset = self.data.find(query_bytes, offset)
            if offset == -1:
                break
            results.append(f"0x{offset:08x}")
            offset += 1

        if results:
            return f"Found '{query}' at {len(results)} location(s):\n" + "\n".join(results[:100])
        else:
            return f"String '{query}' not found"

    # ========== CROSS-REFERENCE ANALYSIS ==========

    def analyze_xrefs(self):
        """Analyze cross-references (calls, jumps, data refs) like IDA Pro"""
        if not self.pe:
            return "No file loaded"

        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP
        except ImportError:
            return "Capstone not installed"

        # Determine architecture
        if self.pe.FILE_HEADER.Machine == 0x14c:  # x86
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            ptr_size = 4
        elif self.pe.FILE_HEADER.Machine == 0x8664:  # x64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            ptr_size = 8
        else:
            return "Unsupported architecture"

        md.detail = True  # Enable detailed instruction info

        # Initialize xrefs database
        self.xrefs = {}
        self.instructions = {}

        # Analyze .text section
        for section in self.pe.sections:
            if b'.text' in section.Name:
                section_data = section.get_data()
                rva = section.VirtualAddress
                image_base = self.pe.OPTIONAL_HEADER.ImageBase

                # Disassemble and build xrefs
                for instr in md.disasm(section_data, rva):
                    addr = instr.address + image_base

                    # Store instruction info
                    self.instructions[addr] = {
                        'mnemonic': instr.mnemonic,
                        'op_str': instr.op_str,
                        'bytes': instr.bytes,
                        'size': instr.size
                    }

                    # Initialize xref entry for this address
                    if addr not in self.xrefs:
                        self.xrefs[addr] = {
                            'calls_to': [],
                            'called_from': [],
                            'jumps_to': [],
                            'jumped_from': [],
                            'data_refs': []
                        }

                    # Check if it's a call instruction
                    if CS_GRP_CALL in instr.groups:
                        # Try to get target address
                        target = self._get_call_target(instr, addr, image_base)
                        if target:
                            # Add "calls to" for current address
                            self.xrefs[addr]['calls_to'].append(target)

                            # Add "called from" for target
                            if target not in self.xrefs:
                                self.xrefs[target] = {
                                    'calls_to': [], 'called_from': [],
                                    'jumps_to': [], 'jumped_from': [],
                                    'data_refs': []
                                }
                            self.xrefs[target]['called_from'].append(addr)

                    # Check if it's a jump instruction
                    elif CS_GRP_JUMP in instr.groups:
                        target = self._get_jump_target(instr, addr, image_base)
                        if target:
                            self.xrefs[addr]['jumps_to'].append(target)

                            if target not in self.xrefs:
                                self.xrefs[target] = {
                                    'calls_to': [], 'called_from': [],
                                    'jumps_to': [], 'jumped_from': [],
                                    'data_refs': []
                                }
                            self.xrefs[target]['jumped_from'].append(addr)

        return True

    def _get_call_target(self, instr, current_addr, image_base):
        """Extract call target address"""
        try:
            # Check if it's a direct call with immediate operand
            if 'call' in instr.mnemonic and len(instr.operands) > 0:
                op = instr.operands[0]
                if op.type == 2:  # Immediate
                    return op.imm
        except:
            pass
        return None

    def _get_jump_target(self, instr, current_addr, image_base):
        """Extract jump target address"""
        try:
            if len(instr.operands) > 0:
                op = instr.operands[0]
                if op.type == 2:  # Immediate
                    return op.imm
        except:
            pass
        return None

    def get_xrefs_to(self, address):
        """Get all cross-references TO an address (what calls/jumps to it)"""
        if address not in self.xrefs:
            return None

        xref_data = self.xrefs[address]
        result = []

        if xref_data['called_from']:
            result.append("Called from:")
            for addr in xref_data['called_from']:
                result.append(f"  0x{addr:016x}")

        if xref_data['jumped_from']:
            result.append("\nJumped from:")
            for addr in xref_data['jumped_from']:
                result.append(f"  0x{addr:016x}")

        return "\n".join(result) if result else "No xrefs to this address"

    def get_xrefs_from(self, address):
        """Get all cross-references FROM an address (what it calls/jumps to)"""
        if address not in self.xrefs:
            return None

        xref_data = self.xrefs[address]
        result = []

        if xref_data['calls_to']:
            result.append("Calls to:")
            for addr in xref_data['calls_to']:
                result.append(f"  0x{addr:016x}")

        if xref_data['jumps_to']:
            result.append("\nJumps to:")
            for addr in xref_data['jumps_to']:
                result.append(f"  0x{addr:016x}")

        return "\n".join(result) if result else "No xrefs from this address"

    def get_xref_summary(self):
        """Get summary of all cross-references"""
        if not self.xrefs:
            return "No xref analysis performed yet. Run 'Analyze Cross-References' first."

        result = []
        result.append("=" * 80)
        result.append("CROSS-REFERENCE ANALYSIS (Like IDA Pro)")
        result.append("=" * 80)
        result.append("")

        # Count statistics
        total_calls = sum(len(x['calls_to']) for x in self.xrefs.values())
        total_jumps = sum(len(x['jumps_to']) for x in self.xrefs.values())

        result.append(f"Total Instructions Analyzed: {len(self.instructions)}")
        result.append(f"Total Call Instructions: {total_calls}")
        result.append(f"Total Jump Instructions: {total_jumps}")
        result.append(f"Total Addresses with XRefs: {len(self.xrefs)}")
        result.append("")

        # Find most called functions
        call_counts = {}
        for addr, xref_data in self.xrefs.items():
            if xref_data['called_from']:
                call_counts[addr] = len(xref_data['called_from'])

        if call_counts:
            result.append("Most Called Functions (Top 20):")
            result.append(f"{'Address':<18} {'Times Called':<15} {'Xrefs'}")
            result.append("-" * 80)

            sorted_funcs = sorted(call_counts.items(), key=lambda x: x[1], reverse=True)[:20]
            for addr, count in sorted_funcs:
                result.append(f"0x{addr:016x}  {count:<15}")

                # Show first 3 callers
                callers = self.xrefs[addr]['called_from'][:3]
                for caller in callers:
                    result.append(f"  ← 0x{caller:016x}")
                if len(self.xrefs[addr]['called_from']) > 3:
                    result.append(f"  ... and {len(self.xrefs[addr]['called_from']) - 3} more")

        result.append("")
        result.append("=" * 80)
        result.append("Usage:")
        result.append("  - Right-click on any address in disassembly to see xrefs")
        result.append("  - View → Cross-References to see this summary")
        result.append("=" * 80)

        return "\n".join(result)

    def get_function_callers(self, function_addr):
        """Get list of functions that call a specific function"""
        if function_addr not in self.xrefs:
            return []
        return self.xrefs[function_addr]['called_from']

    def get_function_callees(self, function_addr):
        """Get list of functions called by a specific function"""
        if function_addr not in self.xrefs:
            return []
        return self.xrefs[function_addr]['calls_to']
