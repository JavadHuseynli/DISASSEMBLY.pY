"""
EXE Analyzer - A Visual Disassembler and Binary Analysis Tool
For legitimate security analysis, malware research, and educational purposes only.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import re
from analyzer_core import ExeAnalyzer
from ui_components import HexViewer, DisassemblyViewer, StructureViewer
from instruction_help import InstructionHelper


class ExeAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("EXE Analyzer - Binary Disassembler & Reverse Engineering Tool")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2b2b2b')

        self.analyzer = None
        self.current_file = None

        # Zoom settings
        self.zoom_level = 100  # Default 100%
        self.text_widgets = []  # Will store all text widgets for zoom

        # Instruction help system
        self.instruction_helper = InstructionHelper()
        self.help_window = None  # Instruction help window

        self._create_menu_bar()
        self._create_toolbar()
        self._create_main_interface()
        self._create_status_bar()

    def _create_menu_bar(self):
        """Create top menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open EXE/DLL...", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Open .NET Assembly...", command=self.open_dotnet_file)
        file_menu.add_separator()
        file_menu.add_command(label="Export Disassembly...", command=self.export_disassembly)
        file_menu.add_command(label="Export Hex Dump...", command=self.export_hex)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Analysis Menu
        analysis_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Analysis", menu=analysis_menu)
        analysis_menu.add_command(label="Analyze PE Structure", command=self.analyze_pe_structure)
        analysis_menu.add_command(label="Disassemble Code", command=self.disassemble_code)
        analysis_menu.add_command(label="Extract Strings", command=self.extract_strings)
        analysis_menu.add_command(label="Find Imports/Exports", command=self.show_imports_exports)
        analysis_menu.add_separator()
        analysis_menu.add_command(label="Analyze Cross-References (XRefs)", command=self.analyze_xrefs)
        analysis_menu.add_separator()
        analysis_menu.add_command(label="Detect Packer/Obfuscation", command=self.detect_packer)

        # View Menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Hex View", command=lambda: self.switch_view("hex"))
        view_menu.add_command(label="Disassembly View", command=lambda: self.switch_view("disasm"))
        view_menu.add_command(label="Structure View", command=lambda: self.switch_view("structure"))
        view_menu.add_separator()

        # Zoom submenu
        zoom_menu = tk.Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Zoom", menu=zoom_menu)
        zoom_menu.add_command(label="Zoom In", command=self.zoom_in, accelerator="Ctrl++")
        zoom_menu.add_command(label="Zoom Out", command=self.zoom_out, accelerator="Ctrl+-")
        zoom_menu.add_command(label="Reset Zoom", command=self.zoom_reset, accelerator="Ctrl+0")
        zoom_menu.add_separator()
        zoom_menu.add_command(label="50%", command=lambda: self.set_zoom(50))
        zoom_menu.add_command(label="75%", command=lambda: self.set_zoom(75))
        zoom_menu.add_command(label="100% (Default)", command=lambda: self.set_zoom(100))
        zoom_menu.add_command(label="125%", command=lambda: self.set_zoom(125))
        zoom_menu.add_command(label="150%", command=lambda: self.set_zoom(150))
        zoom_menu.add_command(label="200%", command=lambda: self.set_zoom(200))

        view_menu.add_separator()
        view_menu.add_checkbutton(label="Show Opcodes", command=self.toggle_opcodes)
        view_menu.add_checkbutton(label="Show Comments", command=self.toggle_comments)

        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="String Search...", command=self.string_search)
        tools_menu.add_command(label="Byte Pattern Search...", command=self.pattern_search)
        tools_menu.add_command(label="Calculate Entropy", command=self.calculate_entropy)
        tools_menu.add_command(label="Compare Files...", command=self.compare_files)

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)

        # Keyboard shortcuts
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-s>', lambda e: self.export_disassembly())

        # Zoom shortcuts
        self.root.bind('<Control-plus>', lambda e: self.zoom_in())
        self.root.bind('<Control-equal>', lambda e: self.zoom_in())  # Ctrl+= also works as Ctrl++
        self.root.bind('<Control-minus>', lambda e: self.zoom_out())
        self.root.bind('<Control-0>', lambda e: self.zoom_reset())

    def _create_toolbar(self):
        """Create toolbar with quick action buttons"""
        toolbar = tk.Frame(self.root, bg='#1e1e1e', relief=tk.RAISED, bd=2)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        # Dark theme button style - Dark gray/black with light text
        btn_style = {
            'bg': '#2d2d2d',                # Dark gray background
            'fg': '#e0e0e0',                # Light gray text
            'activebackground': '#454545',  # Lighter when clicked
            'activeforeground': '#ffffff',  # White when active
            'relief': tk.RAISED,            # Raised relief for better visibility
            'padx': 12,
            'pady': 6,
            'borderwidth': 1,
            'highlightthickness': 0,
            'highlightbackground': '#1e1e1e',
            'highlightcolor': '#1e1e1e',
            'font': ('Arial', 9, 'bold'),
            'cursor': 'hand2'               # Hand cursor on hover
        }

        # Create buttons and store references
        self.btn_open = tk.Button(toolbar, text="📁 Open", command=self.open_file, **btn_style)
        self.btn_open.pack(side=tk.LEFT, padx=2, pady=2)

        self.btn_analyze = tk.Button(toolbar, text="🔍 Analyze", command=self.analyze_pe_structure, **btn_style)
        self.btn_analyze.pack(side=tk.LEFT, padx=2, pady=2)

        self.btn_disasm = tk.Button(toolbar, text="⚙️ Disassemble", command=self.disassemble_code, **btn_style)
        self.btn_disasm.pack(side=tk.LEFT, padx=2, pady=2)

        self.btn_strings = tk.Button(toolbar, text="🔤 Strings", command=self.extract_strings, **btn_style)
        self.btn_strings.pack(side=tk.LEFT, padx=2, pady=2)

        self.btn_xrefs = tk.Button(toolbar, text="🔗 XRefs", command=self.analyze_xrefs, **btn_style)
        self.btn_xrefs.pack(side=tk.LEFT, padx=2, pady=2)

        self.btn_hex = tk.Button(toolbar, text="📊 Hex View", command=lambda: self.switch_view("hex"), **btn_style)
        self.btn_hex.pack(side=tk.LEFT, padx=2, pady=2)

        # Separator
        tk.Frame(toolbar, bg='#404040', width=2, height=30).pack(side=tk.LEFT, padx=10, pady=2)

        # Zoom controls
        self.btn_zoom_in = tk.Button(toolbar, text="🔍+", command=self.zoom_in, **btn_style, width=3)
        self.btn_zoom_in.pack(side=tk.LEFT, padx=2, pady=2)

        self.btn_zoom_out = tk.Button(toolbar, text="🔍-", command=self.zoom_out, **btn_style, width=3)
        self.btn_zoom_out.pack(side=tk.LEFT, padx=2, pady=2)

        # Force button colors (ensure dark theme on startup)
        for btn in [self.btn_open, self.btn_analyze, self.btn_disasm, self.btn_strings,
                    self.btn_xrefs, self.btn_hex, self.btn_zoom_in, self.btn_zoom_out]:
            btn.configure(bg='#2d2d2d', fg='#e0e0e0')
            # Bind hover effects
            btn.bind('<Enter>', lambda e, b=btn: b.configure(bg='#404040'))
            btn.bind('<Leave>', lambda e, b=btn: b.configure(bg='#2d2d2d'))

        self.zoom_label = tk.Label(toolbar, text="100%", bg='#1e1e1e', fg='#00ff00', font=('Arial', 10, 'bold'), width=5)
        self.zoom_label.pack(side=tk.LEFT, padx=5)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(toolbar, variable=self.progress_var, mode='determinate', length=200)
        self.progress_bar.pack(side=tk.RIGHT, padx=10, pady=5)

        self.progress_label = tk.Label(toolbar, text="Ready", bg='#1e1e1e', fg='#e0e0e0', font=('Arial', 9))
        self.progress_label.pack(side=tk.RIGHT, padx=5)

    def _create_main_interface(self):
        """Create main interface with notebook tabs"""
        # Main container
        main_container = tk.Frame(self.root, bg='#2b2b2b')
        main_container.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Left panel - File info
        left_panel = tk.Frame(main_container, bg='#3c3c3c', width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        left_panel.pack_propagate(False)

        tk.Label(left_panel, text="File Information", bg='#3c3c3c', fg='white',
                font=('Arial', 12, 'bold')).pack(pady=5)

        self.file_info_text = scrolledtext.ScrolledText(left_panel, bg='#2b2b2b', fg='#00ff00',
                                                        font=('Courier', 9), wrap=tk.WORD)
        self.file_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.text_widgets.append(self.file_info_text)

        # Right panel - Main views
        right_panel = tk.Frame(main_container, bg='#2b2b2b')
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Notebook for different views
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Overview Tab
        self.overview_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.overview_frame, text="Overview")

        self.overview_text = scrolledtext.ScrolledText(self.overview_frame, bg='#2b2b2b',
                                                       fg='white', font=('Courier', 10))
        self.overview_text.pack(fill=tk.BOTH, expand=True)
        self.text_widgets.append(self.overview_text)

        # Disassembly Tab
        self.disasm_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.disasm_frame, text="Disassembly")

        self.disasm_text = scrolledtext.ScrolledText(self.disasm_frame, bg='#1e1e1e',
                                                     fg='#dcdcdc', font=('Courier', 10), cursor='hand2')
        self.disasm_text.pack(fill=tk.BOTH, expand=True)
        self.text_widgets.append(self.disasm_text)

        # Configure syntax highlighting tags for disassembly
        self.disasm_text.tag_config('address', foreground='#808080')
        self.disasm_text.tag_config('bytes', foreground='#569cd6')
        self.disasm_text.tag_config('mnemonic', foreground='#4ec9b0', font=('Courier', 10, 'bold'))
        self.disasm_text.tag_config('register', foreground='#ce9178')
        self.disasm_text.tag_config('immediate', foreground='#b5cea8')
        self.disasm_text.tag_config('comment', foreground='#6a9955')
        self.disasm_text.tag_config('clickable', foreground='#4ec9b0', underline=True)

        # Bind click event to show instruction help
        self.disasm_text.bind('<Button-1>', self.on_disasm_click)
        self.disasm_text.bind('<Motion>', self.on_disasm_hover)

        # Hex View Tab
        self.hex_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.hex_frame, text="Hex View")

        self.hex_text = scrolledtext.ScrolledText(self.hex_frame, bg='#1e1e1e',
                                                  fg='#00ff00', font=('Courier', 9))
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        self.text_widgets.append(self.hex_text)

        # Strings Tab
        self.strings_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.strings_frame, text="Strings")

        self.strings_text = scrolledtext.ScrolledText(self.strings_frame, bg='#1e1e1e',
                                                      fg='#ffff00', font=('Courier', 9))
        self.strings_text.pack(fill=tk.BOTH, expand=True)
        self.text_widgets.append(self.strings_text)

        # Imports/Exports Tab
        self.imports_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.imports_frame, text="Imports/Exports")

        self.imports_text = scrolledtext.ScrolledText(self.imports_frame, bg='#1e1e1e',
                                                      fg='#87ceeb', font=('Courier', 9))
        self.imports_text.pack(fill=tk.BOTH, expand=True)
        self.text_widgets.append(self.imports_text)

        # Sections Tab
        self.sections_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.sections_frame, text="Sections")

        self.sections_text = scrolledtext.ScrolledText(self.sections_frame, bg='#1e1e1e',
                                                       fg='#ffa500', font=('Courier', 9))
        self.sections_text.pack(fill=tk.BOTH, expand=True)
        self.text_widgets.append(self.sections_text)

        # Cross-References Tab
        self.xrefs_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.xrefs_frame, text="Cross-Refs")

        self.xrefs_text = scrolledtext.ScrolledText(self.xrefs_frame, bg='#1e1e1e',
                                                    fg='#00ffff', font=('Courier', 9), cursor='hand2')
        self.xrefs_text.pack(fill=tk.BOTH, expand=True)
        self.text_widgets.append(self.xrefs_text)

        # Bind click event to show function details in XRef view
        self.xrefs_text.bind('<Button-1>', self.on_xref_click)
        self.xrefs_text.bind('<Motion>', self.on_xref_hover)

    def _create_status_bar(self):
        """Create bottom status bar"""
        status_bar = tk.Frame(self.root, bg='#3c3c3c', relief=tk.SUNKEN, bd=1)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = tk.Label(status_bar, text="Ready", bg='#3c3c3c', fg='white', anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, padx=10)

        self.file_size_label = tk.Label(status_bar, text="", bg='#3c3c3c', fg='white')
        self.file_size_label.pack(side=tk.RIGHT, padx=10)

        self.file_type_label = tk.Label(status_bar, text="", bg='#3c3c3c', fg='white')
        self.file_type_label.pack(side=tk.RIGHT, padx=10)

    def update_progress(self, value, text="Processing..."):
        """Update progress bar"""
        self.progress_var.set(value)
        self.progress_label.config(text=text)
        self.root.update_idletasks()

    def update_status(self, message):
        """Update status bar"""
        self.status_label.config(text=message)
        self.root.update_idletasks()

    def open_file(self):
        """Open and analyze executable file"""
        file_path = filedialog.askopenfilename(
            title="Select Executable File",
            filetypes=[
                ("Executable Files", "*.exe *.dll"),
                (".NET Assemblies", "*.exe *.dll"),
                ("All Files", "*.*")
            ]
        )

        if not file_path:
            return

        self.current_file = file_path
        self.update_status(f"Loading: {os.path.basename(file_path)}")

        # Load file in separate thread
        thread = threading.Thread(target=self._load_file_thread, args=(file_path,))
        thread.daemon = True
        thread.start()

    def _load_file_thread(self, file_path):
        """Load file in background thread"""
        try:
            self.update_progress(10, "Loading file...")
            self.analyzer = ExeAnalyzer(file_path)

            self.update_progress(30, "Parsing PE structure...")
            self.analyzer.parse_pe()

            self.update_progress(50, "Analyzing sections...")
            self._display_file_info()

            self.update_progress(70, "Generating overview...")
            self._display_overview()

            self.update_progress(90, "Extracting strings...")
            self.extract_strings()

            self.update_progress(100, "Complete")
            self.update_status(f"Loaded: {os.path.basename(file_path)}")

            # Update status bar
            file_size = os.path.getsize(file_path)
            self.file_size_label.config(text=f"Size: {file_size:,} bytes")
            self.file_type_label.config(text=f"Type: {self.analyzer.get_file_type()}")

        except Exception as e:
            self.update_progress(0, "Error")
            messagebox.showerror("Error", f"Failed to load file:\n{str(e)}")
            self.update_status("Error loading file")

    def _display_file_info(self):
        """Display file information"""
        if not self.analyzer:
            return

        self.file_info_text.delete('1.0', tk.END)
        info = self.analyzer.get_file_info()
        self.file_info_text.insert('1.0', info)

    def _display_overview(self):
        """Display file overview"""
        if not self.analyzer:
            return

        self.overview_text.delete('1.0', tk.END)
        overview = self.analyzer.get_overview()
        self.overview_text.insert('1.0', overview)

    def open_dotnet_file(self):
        """Open .NET assembly"""
        file_path = filedialog.askopenfilename(
            title="Select .NET Assembly",
            filetypes=[(".NET Assembly", "*.exe *.dll"), ("All Files", "*.*")]
        )

        if file_path:
            self.update_status(".NET analysis not fully implemented yet")
            messagebox.showinfo("Info", "Opening .NET file. Advanced .NET analysis coming soon!")
            # Use dnfile library for .NET analysis

    def analyze_pe_structure(self):
        """Analyze PE structure in detail"""
        if not self.analyzer:
            messagebox.showwarning("Warning", "Please open a file first")
            return

        self.update_status("Analyzing PE structure...")
        self.update_progress(0, "Analyzing...")

        thread = threading.Thread(target=self._analyze_pe_thread)
        thread.daemon = True
        thread.start()

    def _analyze_pe_thread(self):
        """Analyze PE structure in background"""
        try:
            self.update_progress(20, "Analyzing headers...")
            sections_info = self.analyzer.analyze_sections()

            self.update_progress(50, "Analyzing imports...")
            self.show_imports_exports()

            self.update_progress(80, "Analyzing sections...")
            self.sections_text.delete('1.0', tk.END)
            self.sections_text.insert('1.0', sections_info)

            self.update_progress(100, "Complete")
            self.update_status("PE analysis complete")

            # Switch to sections tab
            self.notebook.select(self.sections_frame)

        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed:\n{str(e)}")
            self.update_progress(0, "Error")

    def disassemble_code(self):
        """Disassemble executable code"""
        if not self.analyzer:
            messagebox.showwarning("Warning", "Please open a file first")
            return

        self.update_status("Disassembling...")
        thread = threading.Thread(target=self._disassemble_thread)
        thread.daemon = True
        thread.start()

    def _disassemble_thread(self):
        """Disassemble in background thread"""
        try:
            self.update_progress(10, "Starting disassembly...")

            disasm = self.analyzer.disassemble()

            self.update_progress(80, "Formatting output...")
            self.disasm_text.delete('1.0', tk.END)
            self.disasm_text.insert('1.0', disasm)

            self.update_progress(100, "Complete")
            self.update_status("Disassembly complete")

            # Switch to disassembly tab
            self.notebook.select(self.disasm_frame)

        except Exception as e:
            messagebox.showerror("Error", f"Disassembly failed:\n{str(e)}")
            self.update_progress(0, "Error")

    def extract_strings(self):
        """Extract strings from binary"""
        if not self.analyzer:
            return

        try:
            self.update_status("Extracting strings...")
            strings = self.analyzer.extract_strings()

            self.strings_text.delete('1.0', tk.END)
            self.strings_text.insert('1.0', strings)

            self.update_status("Strings extracted")
        except Exception as e:
            messagebox.showerror("Error", f"String extraction failed:\n{str(e)}")

    def show_imports_exports(self):
        """Show imports and exports"""
        if not self.analyzer:
            return

        try:
            imports_exports = self.analyzer.get_imports_exports()
            self.imports_text.delete('1.0', tk.END)
            self.imports_text.insert('1.0', imports_exports)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to get imports/exports:\n{str(e)}")

    def analyze_xrefs(self):
        """Analyze cross-references (calls, jumps) like IDA Pro"""
        if not self.analyzer:
            messagebox.showwarning("Warning", "Please open a file first")
            return

        self.update_status("Analyzing cross-references...")
        thread = threading.Thread(target=self._analyze_xrefs_thread)
        thread.daemon = True
        thread.start()

    def _analyze_xrefs_thread(self):
        """Analyze xrefs in background thread"""
        try:
            self.update_progress(10, "Analyzing calls...")

            # Perform xref analysis
            result = self.analyzer.analyze_xrefs()

            self.update_progress(70, "Building xref database...")

            if result:
                # Get summary
                xref_summary = self.analyzer.get_xref_summary()

                self.update_progress(90, "Displaying results...")

                # Display in xrefs tab
                self.xrefs_text.delete('1.0', tk.END)
                self.xrefs_text.insert('1.0', xref_summary)

                self.update_progress(100, "Complete")
                self.update_status("Cross-reference analysis complete")

                # Switch to xrefs tab
                self.notebook.select(self.xrefs_frame)

                messagebox.showinfo("Success",
                    f"Cross-reference analysis complete!\n\n" +
                    f"Analyzed {len(self.analyzer.instructions)} instructions\n" +
                    f"Found {len(self.analyzer.xrefs)} addresses with xrefs\n\n" +
                    "View the Cross-Refs tab for details.")
            else:
                self.update_progress(0, "Error")
                messagebox.showerror("Error", "Failed to analyze cross-references")

        except Exception as e:
            self.update_progress(0, "Error")
            messagebox.showerror("Error", f"Cross-reference analysis failed:\n{str(e)}")

    def switch_view(self, view_name):
        """Switch between different views"""
        if view_name == "hex":
            if not self.analyzer:
                return
            self.update_status("Generating hex view...")
            hex_data = self.analyzer.get_hex_dump()
            self.hex_text.delete('1.0', tk.END)
            self.hex_text.insert('1.0', hex_data)
            self.notebook.select(self.hex_frame)
        elif view_name == "disasm":
            self.notebook.select(self.disasm_frame)
        elif view_name == "structure":
            self.notebook.select(self.sections_frame)

    def detect_packer(self):
        """Detect if file is packed or obfuscated"""
        if not self.analyzer:
            messagebox.showwarning("Warning", "Please open a file first")
            return

        result = self.analyzer.detect_packer()
        messagebox.showinfo("Packer Detection", result)

    def calculate_entropy(self):
        """Calculate file entropy"""
        if not self.analyzer:
            messagebox.showwarning("Warning", "Please open a file first")
            return

        entropy = self.analyzer.calculate_entropy()
        messagebox.showinfo("Entropy Analysis", f"File Entropy: {entropy:.4f}\n\n" +
                           "High entropy (>7.0) may indicate compression or encryption.")

    def export_disassembly(self):
        """Export disassembly to file"""
        if not self.analyzer:
            messagebox.showwarning("Warning", "Please open a file first")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".asm",
            filetypes=[("Assembly File", "*.asm"), ("Text File", "*.txt")]
        )

        if file_path:
            content = self.disasm_text.get('1.0', tk.END)
            with open(file_path, 'w') as f:
                f.write(content)
            messagebox.showinfo("Success", "Disassembly exported successfully")

    def export_hex(self):
        """Export hex dump to file"""
        if not self.analyzer:
            messagebox.showwarning("Warning", "Please open a file first")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".hex",
            filetypes=[("Hex Dump", "*.hex"), ("Text File", "*.txt")]
        )

        if file_path:
            hex_data = self.analyzer.get_hex_dump()
            with open(file_path, 'w') as f:
                f.write(hex_data)
            messagebox.showinfo("Success", "Hex dump exported successfully")

    def string_search(self):
        """Search for strings in binary"""
        search_window = tk.Toplevel(self.root)
        search_window.title("String Search")
        search_window.geometry("400x150")

        tk.Label(search_window, text="Search for:").pack(pady=10)
        search_entry = tk.Entry(search_window, width=50)
        search_entry.pack(pady=5)

        def do_search():
            query = search_entry.get()
            if query and self.analyzer:
                results = self.analyzer.search_string(query)
                messagebox.showinfo("Search Results", results)

        tk.Button(search_window, text="Search", command=do_search).pack(pady=10)

    def pattern_search(self):
        """Search for byte patterns"""
        messagebox.showinfo("Info", "Byte pattern search - Coming soon!")

    def compare_files(self):
        """Compare two files"""
        messagebox.showinfo("Info", "File comparison - Coming soon!")

    def toggle_opcodes(self):
        """Toggle opcode display"""
        messagebox.showinfo("Info", "Toggle opcodes - Feature coming soon!")

    def toggle_comments(self):
        """Toggle comments in disassembly"""
        messagebox.showinfo("Info", "Toggle comments - Feature coming soon!")

    def show_documentation(self):
        """Show documentation"""
        doc_window = tk.Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("600x400")

        doc_text = scrolledtext.ScrolledText(doc_window, wrap=tk.WORD)
        doc_text.pack(fill=tk.BOTH, expand=True)

        doc_content = """
EXE ANALYZER - DOCUMENTATION

This tool is designed for legitimate security research, malware analysis,
and educational purposes only.

FEATURES:
1. PE File Analysis - Analyze Windows executable structure
2. Disassembly - Disassemble x86/x64 code
3. Hex Viewer - View raw binary data
4. String Extraction - Extract readable strings
5. Import/Export Analysis - View imported/exported functions
6. .NET Support - Basic .NET assembly analysis
7. Packer Detection - Detect common packers

USAGE:
1. Open an .exe or .dll file using File > Open
2. Use Analysis menu for different analysis options
3. View results in different tabs
4. Export results using File > Export options

KEYBOARD SHORTCUTS:
Ctrl+O - Open file
Ctrl+S - Export disassembly

LEGAL NOTICE:
This tool is for authorized security research only.
Do not use on files without proper authorization.
        """

        doc_text.insert('1.0', doc_content)
        doc_text.config(state='disabled')

    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About",
            "EXE Analyzer v1.0\n\n" +
            "A Visual Binary Analysis and Reverse Engineering Tool\n\n" +
            "For legitimate security research and educational purposes\n\n" +
            "© 2025 - Built with Python")

    # ========== INTERACTIVE DISASSEMBLY ==========

    def on_disasm_click(self, event):
        """Handle click on disassembly line to show instruction help"""
        try:
            # Get the line that was clicked
            index = self.disasm_text.index(f"@{event.x},{event.y}")
            line_start = self.disasm_text.index(f"{index} linestart")
            line_end = self.disasm_text.index(f"{index} lineend")
            line = self.disasm_text.get(line_start, line_end)

            # Parse the line to extract mnemonic
            mnemonic = self._extract_mnemonic(line)

            if mnemonic:
                self.show_instruction_help(mnemonic, line)
        except Exception as e:
            # Silently ignore errors
            pass

    def on_disasm_hover(self, event):
        """Handle hover over disassembly to show cursor"""
        try:
            # Get the line under cursor
            index = self.disasm_text.index(f"@{event.x},{event.y}")
            line_start = self.disasm_text.index(f"{index} linestart")
            line_end = self.disasm_text.index(f"{index} lineend")
            line = self.disasm_text.get(line_start, line_end)

            # Check if line contains a mnemonic
            mnemonic = self._extract_mnemonic(line)

            if mnemonic:
                self.disasm_text.config(cursor='hand2')
            else:
                self.disasm_text.config(cursor='xterm')
        except:
            self.disasm_text.config(cursor='xterm')

    def _extract_mnemonic(self, line):
        """Extract assembly mnemonic from disassembly line"""
        # Pattern: Address  Bytes  Mnemonic  Operands
        # Example: 0x0000000140001000  48 83 ec 28    sub    rsp, 0x28

        # Try to find mnemonic (word after hex bytes)
        # Skip lines that are headers or empty
        if not line.strip() or '=' in line or 'Address' in line:
            return None

        # Look for pattern: address bytes mnemonic
        parts = line.split()
        if len(parts) < 3:
            return None

        # Find the mnemonic (should be after address and bytes)
        for i, part in enumerate(parts):
            # Skip addresses (0x...)
            if part.startswith('0x'):
                continue
            # Skip hex bytes (two hex digits)
            if re.match(r'^[0-9a-f]{2}$', part, re.IGNORECASE):
                continue
            # This should be the mnemonic
            if re.match(r'^[a-z]+$', part, re.IGNORECASE):
                return part.lower()

        return None

    def show_instruction_help(self, mnemonic, line):
        """Show detailed help for an instruction"""
        # Get help data
        help_data = self.instruction_helper.get_instruction_help(mnemonic)

        # Create or update help window
        if self.help_window is None or not self.help_window.winfo_exists():
            self.help_window = tk.Toplevel(self.root)
            self.help_window.title("Instruction Help")
            self.help_window.geometry("700x600")
            self.help_window.configure(bg='#2b2b2b')

            # Make it stay on top but not always
            self.help_window.transient(self.root)

            # Create text widget
            help_frame = tk.Frame(self.help_window, bg='#2b2b2b')
            help_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            self.help_text = scrolledtext.ScrolledText(
                help_frame,
                bg='#1e1e1e',
                fg='#dcdcdc',
                font=('Courier', 10),
                wrap=tk.WORD,
                padx=10,
                pady=10
            )
            self.help_text.pack(fill=tk.BOTH, expand=True)

            # Configure tags
            self.help_text.tag_config('title', foreground='#4ec9b0', font=('Courier', 12, 'bold'))
            self.help_text.tag_config('category', foreground='#569cd6', font=('Courier', 10, 'bold'))
            self.help_text.tag_config('syntax', foreground='#ce9178', font=('Courier', 10, 'bold'))
            self.help_text.tag_config('example', foreground='#b5cea8')
            self.help_text.tag_config('bullet', foreground='#00ff00')

            # Add close button
            btn_frame = tk.Frame(self.help_window, bg='#2b2b2b')
            btn_frame.pack(fill=tk.X, padx=10, pady=5)

            tk.Button(
                btn_frame,
                text="Close",
                command=self.help_window.destroy,
                bg='#4c4c4c',
                fg='white',
                relief=tk.FLAT,
                padx=20,
                pady=5
            ).pack(side=tk.RIGHT)

        # Clear and update content
        self.help_text.delete('1.0', tk.END)

        # Format and display help
        self.help_text.insert(tk.END, f"{'='*70}\n")
        self.help_text.insert(tk.END, f"  {mnemonic.upper()} - {help_data['description']}\n", 'title')
        self.help_text.insert(tk.END, f"{'='*70}\n\n")

        self.help_text.insert(tk.END, f"Category: ", 'category')
        self.help_text.insert(tk.END, f"{help_data['category']}\n\n")

        self.help_text.insert(tk.END, f"Syntax: ", 'syntax')
        self.help_text.insert(tk.END, f"{help_data['syntax']}\n\n")

        self.help_text.insert(tk.END, "WHAT IT DOES:\n", 'category')
        self.help_text.insert(tk.END, f"  {help_data['explanation']}\n\n")

        self.help_text.insert(tk.END, "EXAMPLE:\n", 'category')
        self.help_text.insert(tk.END, f"  {help_data['example']}\n\n", 'example')

        self.help_text.insert(tk.END, "AFFECTS:\n", 'category')
        self.help_text.insert(tk.END, f"  {help_data['affects']}\n\n")

        self.help_text.insert(tk.END, "COMMON USES:\n", 'category')
        for use in help_data['common_uses']:
            self.help_text.insert(tk.END, "  • ", 'bullet')
            self.help_text.insert(tk.END, f"{use}\n")

        self.help_text.insert(tk.END, f"\n{'='*70}\n")
        self.help_text.insert(tk.END, "💡 TIP: Click any instruction in disassembly to see its explanation!\n")
        self.help_text.insert(tk.END, f"{'='*70}\n")

        # Show the clicked line context
        self.help_text.insert(tk.END, f"\nYou clicked:\n", 'category')
        self.help_text.insert(tk.END, f"  {line.strip()}\n", 'example')

        # Make readonly
        self.help_text.config(state='disabled')

        # Bring window to front
        self.help_window.lift()
        self.help_window.focus()

        # Update status
        self.update_status(f"Showing help for: {mnemonic.upper()}")

    # ========== XREF CLICK FUNCTIONALITY ==========

    def on_xref_click(self, event):
        """Handle click on XRef line to show function details"""
        try:
            # Get the line that was clicked
            index = self.xrefs_text.index(f"@{event.x},{event.y}")
            line_start = self.xrefs_text.index(f"{index} linestart")
            line_end = self.xrefs_text.index(f"{index} lineend")
            line = self.xrefs_text.get(line_start, line_end)

            # Extract address from the line
            address = self._extract_address_from_xref(line)
            if address:
                self.show_function_details(address, line)

        except Exception as e:
            pass  # Click on non-address line

    def on_xref_hover(self, event):
        """Change cursor when hovering over XRef addresses"""
        try:
            index = self.xrefs_text.index(f"@{event.x},{event.y}")
            line_start = self.xrefs_text.index(f"{index} linestart")
            line_end = self.xrefs_text.index(f"{index} lineend")
            line = self.xrefs_text.get(line_start, line_end)

            # If line contains an address, show hand cursor
            if self._extract_address_from_xref(line):
                self.xrefs_text.config(cursor='hand2')
            else:
                self.xrefs_text.config(cursor='')
        except:
            self.xrefs_text.config(cursor='')

    def _extract_address_from_xref(self, line):
        """Extract hex address from XRef line"""
        import re
        # Look for hex addresses like 0x0000000140001620 or 0x140001620
        match = re.search(r'0x[0-9a-fA-F]{8,16}', line)
        if match:
            return int(match.group(), 16)
        return None

    def show_function_details(self, address, clicked_line):
        """Show detailed information about a function when clicked in XRef"""
        if not self.analyzer:
            return

        # Create or reuse function details window
        if hasattr(self, 'function_window') and self.function_window and self.function_window.winfo_exists():
            self.function_window.lift()
            func_text = self.function_window.children['!scrolledtext']
            func_text.config(state='normal')
            func_text.delete('1.0', tk.END)
        else:
            self.function_window = tk.Toplevel(self.root)
            self.function_window.title("Function Details - Click to Learn!")
            self.function_window.geometry("900x700")
            self.function_window.configure(bg='#1e1e1e')

            func_text = scrolledtext.ScrolledText(
                self.function_window,
                bg='#1e1e1e',
                fg='#e0e0e0',
                font=('Courier', 10),
                wrap=tk.WORD
            )
            func_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Configure color tags
            func_text.tag_config('header', foreground='#00ff00', font=('Courier', 12, 'bold'))
            func_text.tag_config('address', foreground='#569cd6', font=('Courier', 11, 'bold'))
            func_text.tag_config('label', foreground='#ffa500', font=('Courier', 10, 'bold'))
            func_text.tag_config('value', foreground='#00ffff')
            func_text.tag_config('code', foreground='#4ec9b0', font=('Courier', 9))
            func_text.tag_config('important', foreground='#ff6b6b', font=('Courier', 10, 'bold'))

        # Build function details
        func_text.insert(tk.END, "=" * 90 + "\n")
        func_text.insert(tk.END, f"  FUNCTION ANALYSIS - Address: 0x{address:016x}\n", 'header')
        func_text.insert(tk.END, "=" * 90 + "\n\n")

        # Show clicked line
        func_text.insert(tk.END, "📍 You clicked:\n", 'label')
        func_text.insert(tk.END, f"  {clicked_line.strip()}\n\n", 'value')

        # Get XRef data
        xref_data = self.analyzer.xrefs.get(address, {})

        # 1. BASIC INFO
        func_text.insert(tk.END, "=" * 90 + "\n")
        func_text.insert(tk.END, "📊 BASIC INFORMATION\n", 'header')
        func_text.insert(tk.END, "=" * 90 + "\n")
        func_text.insert(tk.END, f"Address:        ", 'label')
        func_text.insert(tk.END, f"0x{address:016x}\n", 'address')

        # Check if this is an instruction we know about
        instr_info = self.analyzer.instructions.get(address, {})
        if instr_info:
            func_text.insert(tk.END, f"Instruction:    ", 'label')
            func_text.insert(tk.END, f"{instr_info.get('mnemonic', '?').upper()} {instr_info.get('op_str', '')}\n", 'code')
            func_text.insert(tk.END, f"Bytes:          ", 'label')
            func_text.insert(tk.END, f"{instr_info.get('bytes', b'').hex()}\n", 'value')
            func_text.insert(tk.END, f"Size:           ", 'label')
            func_text.insert(tk.END, f"{instr_info.get('size', 0)} bytes\n\n", 'value')

        # 2. CALLS TO (What this function calls)
        func_text.insert(tk.END, "=" * 90 + "\n")
        func_text.insert(tk.END, "→ CALLS TO (What this address calls)\n", 'header')
        func_text.insert(tk.END, "=" * 90 + "\n")
        calls_to = xref_data.get('calls_to', [])
        if calls_to:
            func_text.insert(tk.END, f"This function calls {len(calls_to)} other location(s):\n\n", 'important')
            for i, target in enumerate(calls_to[:20], 1):  # Show max 20
                func_text.insert(tk.END, f"  {i}. ", 'label')
                func_text.insert(tk.END, f"0x{target:016x}\n", 'address')
            if len(calls_to) > 20:
                func_text.insert(tk.END, f"\n  ... and {len(calls_to) - 20} more\n", 'value')
        else:
            func_text.insert(tk.END, "  (none) - This doesn't call any functions\n", 'value')
        func_text.insert(tk.END, "\n")

        # 3. CALLED FROM (What calls this function)
        func_text.insert(tk.END, "=" * 90 + "\n")
        func_text.insert(tk.END, "← CALLED FROM (What calls this address)\n", 'header')
        func_text.insert(tk.END, "=" * 90 + "\n")
        called_from = xref_data.get('called_from', [])
        if called_from:
            func_text.insert(tk.END, f"This function is called from {len(called_from)} location(s):\n\n", 'important')
            for i, caller in enumerate(called_from[:20], 1):
                func_text.insert(tk.END, f"  {i}. ", 'label')
                func_text.insert(tk.END, f"0x{caller:016x}\n", 'address')
            if len(called_from) > 20:
                func_text.insert(tk.END, f"\n  ... and {len(called_from) - 20} more\n", 'value')
        else:
            func_text.insert(tk.END, "  (none) - No direct calls to this function found\n", 'value')
        func_text.insert(tk.END, "\n")

        # 4. JUMPS TO
        func_text.insert(tk.END, "=" * 90 + "\n")
        func_text.insert(tk.END, "↗ JUMPS TO (Where this jumps to)\n", 'header')
        func_text.insert(tk.END, "=" * 90 + "\n")
        jumps_to = xref_data.get('jumps_to', [])
        if jumps_to:
            func_text.insert(tk.END, f"This location jumps to {len(jumps_to)} target(s):\n\n", 'important')
            for i, target in enumerate(jumps_to[:20], 1):
                func_text.insert(tk.END, f"  {i}. ", 'label')
                func_text.insert(tk.END, f"0x{target:016x}\n", 'address')
        else:
            func_text.insert(tk.END, "  (none) - No jumps from this location\n", 'value')
        func_text.insert(tk.END, "\n")

        # 5. JUMPED FROM
        func_text.insert(tk.END, "=" * 90 + "\n")
        func_text.insert(tk.END, "↙ JUMPED FROM (What jumps here)\n", 'header')
        func_text.insert(tk.END, "=" * 90 + "\n")
        jumped_from = xref_data.get('jumped_from', [])
        if jumped_from:
            func_text.insert(tk.END, f"This location is jumped to from {len(jumped_from)} location(s):\n\n", 'important')
            for i, jumper in enumerate(jumped_from[:20], 1):
                func_text.insert(tk.END, f"  {i}. ", 'label')
                func_text.insert(tk.END, f"0x{jumper:016x}\n", 'address')
        else:
            func_text.insert(tk.END, "  (none) - No jumps to this location\n", 'value')
        func_text.insert(tk.END, "\n")

        # 6. PURPOSE/ANALYSIS
        func_text.insert(tk.END, "=" * 90 + "\n")
        func_text.insert(tk.END, "🎯 FUNCTION PURPOSE ANALYSIS\n", 'header')
        func_text.insert(tk.END, "=" * 90 + "\n")

        # Determine function purpose based on patterns
        purpose = self._analyze_function_purpose(address, xref_data, instr_info)
        func_text.insert(tk.END, purpose + "\n\n", 'value')

        # Final tip
        func_text.insert(tk.END, "=" * 90 + "\n")
        func_text.insert(tk.END, "💡 TIP: Click any address in Cross-Refs tab to see function details!\n", 'important')
        func_text.insert(tk.END, "=" * 90 + "\n")

        func_text.config(state='disabled')
        self.function_window.lift()

    def _analyze_function_purpose(self, address, xref_data, instr_info):
        """Analyze and guess function purpose based on XRefs and patterns"""
        purpose = []

        called_from_count = len(xref_data.get('called_from', []))
        calls_to_count = len(xref_data.get('calls_to', []))

        # High call count = important utility function
        if called_from_count > 50:
            purpose.append("🔥 HIGHLY USED FUNCTION (50+ callers)")
            purpose.append("   → This is likely a core utility function")
            purpose.append("   → Could be: memory allocation, string operation, logging, etc.")
        elif called_from_count > 20:
            purpose.append("⚡ FREQUENTLY USED (20+ callers)")
            purpose.append("   → Important helper function")
        elif called_from_count > 5:
            purpose.append("✓ COMMONLY USED (5+ callers)")
            purpose.append("   → Regular utility function")
        elif called_from_count == 1:
            purpose.append("→ SINGLE CALLER")
            purpose.append("   → Specialized function or helper")
        elif called_from_count == 0:
            purpose.append("⚠ NO CALLERS FOUND")
            purpose.append("   → Could be: entry point, callback, dead code, or indirect call")

        # Many calls = complex function
        if calls_to_count > 10:
            purpose.append(f"\n📞 MAKES {calls_to_count} CALLS")
            purpose.append("   → Complex function with many operations")
        elif calls_to_count > 0:
            purpose.append(f"\n📞 MAKES {calls_to_count} CALL(S)")
        else:
            purpose.append("\n📞 NO CALLS")
            purpose.append("   → Leaf function (doesn't call others)")

        # Check instruction type
        if instr_info:
            mnemonic = instr_info.get('mnemonic', '').lower()
            if mnemonic in ['call', 'jmp', 'je', 'jne', 'jz', 'jnz']:
                purpose.append(f"\n🎯 INSTRUCTION TYPE: {mnemonic.upper()}")
                if mnemonic == 'call':
                    purpose.append("   → Function call - transfers control to another function")
                elif mnemonic == 'jmp':
                    purpose.append("   → Unconditional jump - goto statement")
                else:
                    purpose.append("   → Conditional jump - if/else logic")

        return "\n".join(purpose) if purpose else "No specific pattern detected."

    # ========== ZOOM FUNCTIONALITY ==========

    def zoom_in(self):
        """Increase zoom level by 10%"""
        self.set_zoom(self.zoom_level + 10)

    def zoom_out(self):
        """Decrease zoom level by 10%"""
        self.set_zoom(self.zoom_level - 10)

    def zoom_reset(self):
        """Reset zoom to 100%"""
        self.set_zoom(100)

    def set_zoom(self, level):
        """Set zoom to specific percentage"""
        # Clamp zoom level between 50% and 300%
        self.zoom_level = max(50, min(300, level))

        # Update zoom label
        self.zoom_label.config(text=f"{self.zoom_level}%")

        # Calculate new font size
        # Base sizes: Courier 9 for hex/strings, Courier 10 for overview/disasm
        base_sizes = [9, 10, 10, 9, 9, 9, 9]  # Corresponding to each text widget

        # Apply zoom to all text widgets
        for i, widget in enumerate(self.text_widgets):
            base_size = base_sizes[i] if i < len(base_sizes) else 10
            new_size = int(base_size * self.zoom_level / 100)
            new_size = max(6, min(48, new_size))  # Clamp between 6 and 48

            # Get current font
            current_font = widget['font']
            if isinstance(current_font, str):
                font_family = 'Courier'
            else:
                font_family = current_font.split()[0] if ' ' in str(current_font) else 'Courier'

            # Update font size
            widget.configure(font=(font_family, new_size))

        # Update status
        self.update_status(f"Zoom level: {self.zoom_level}%")


def main():
    root = tk.Tk()
    app = ExeAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
