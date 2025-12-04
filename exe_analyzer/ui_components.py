"""
UI Components for EXE Analyzer
Contains specialized viewers and widgets
"""

import tkinter as tk
from tkinter import ttk, scrolledtext


class HexViewer:
    """Hex viewer component"""

    def __init__(self, parent):
        self.frame = tk.Frame(parent, bg='#1e1e1e')
        self.text = scrolledtext.ScrolledText(
            self.frame,
            bg='#1e1e1e',
            fg='#00ff00',
            font=('Courier', 9),
            wrap=tk.NONE
        )
        self.text.pack(fill=tk.BOTH, expand=True)

        # Configure tags for syntax highlighting
        self.text.tag_config('offset', foreground='#808080')
        self.text.tag_config('hex', foreground='#00ff00')
        self.text.tag_config('ascii', foreground='#ffff00')

    def display_data(self, data, max_bytes=8192):
        """Display binary data as hex dump"""
        self.text.delete('1.0', tk.END)

        for offset in range(0, min(len(data), max_bytes), 16):
            chunk = data[offset:offset + 16]

            # Offset
            self.text.insert(tk.END, f"{offset:08x}  ", 'offset')

            # Hex bytes
            hex_bytes = ' '.join([f"{b:02x}" for b in chunk])
            self.text.insert(tk.END, f"{hex_bytes:<48}  ", 'hex')

            # ASCII
            ascii_repr = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
            self.text.insert(tk.END, ascii_repr + '\n', 'ascii')

        if len(data) > max_bytes:
            self.text.insert(tk.END, f"\n[Truncated - showing first {max_bytes} bytes]")


class DisassemblyViewer:
    """Disassembly viewer component"""

    def __init__(self, parent):
        self.frame = tk.Frame(parent, bg='#1e1e1e')

        # Create text widget
        self.text = scrolledtext.ScrolledText(
            self.frame,
            bg='#1e1e1e',
            fg='#dcdcdc',
            font=('Courier', 10),
            wrap=tk.NONE
        )
        self.text.pack(fill=tk.BOTH, expand=True)

        # Configure syntax highlighting
        self.text.tag_config('address', foreground='#808080')
        self.text.tag_config('bytes', foreground='#569cd6')
        self.text.tag_config('mnemonic', foreground='#4ec9b0')
        self.text.tag_config('operand', foreground='#ce9178')
        self.text.tag_config('comment', foreground='#6a9955')

    def display_disassembly(self, disasm_data):
        """Display disassembly"""
        self.text.delete('1.0', tk.END)
        self.text.insert('1.0', disasm_data)


class StructureViewer:
    """PE structure viewer component"""

    def __init__(self, parent):
        self.frame = tk.Frame(parent, bg='#2b2b2b')

        # Create tree view
        self.tree = ttk.Treeview(self.frame)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

    def display_pe_structure(self, pe):
        """Display PE structure in tree view"""
        self.tree.delete(*self.tree.get_children())

        # DOS Header
        dos_header = self.tree.insert('', 'end', text='DOS Header', open=True)
        self.tree.insert(dos_header, 'end', text=f'e_magic: 0x{pe.DOS_HEADER.e_magic:04x}')
        self.tree.insert(dos_header, 'end', text=f'e_lfanew: 0x{pe.DOS_HEADER.e_lfanew:x}')

        # NT Headers
        nt_headers = self.tree.insert('', 'end', text='NT Headers', open=True)

        # File Header
        file_header = self.tree.insert(nt_headers, 'end', text='File Header', open=True)
        self.tree.insert(file_header, 'end', text=f'Machine: 0x{pe.FILE_HEADER.Machine:x}')
        self.tree.insert(file_header, 'end', text=f'NumberOfSections: {pe.FILE_HEADER.NumberOfSections}')

        # Optional Header
        opt_header = self.tree.insert(nt_headers, 'end', text='Optional Header', open=True)
        self.tree.insert(opt_header, 'end', text=f'Magic: 0x{pe.OPTIONAL_HEADER.Magic:x}')
        self.tree.insert(opt_header, 'end', text=f'AddressOfEntryPoint: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}')
        self.tree.insert(opt_header, 'end', text=f'ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:x}')

        # Sections
        sections = self.tree.insert('', 'end', text='Sections', open=True)
        for section in pe.sections:
            name = section.Name.decode('utf-8').strip('\x00')
            section_item = self.tree.insert(sections, 'end', text=name, open=False)
            self.tree.insert(section_item, 'end', text=f'VirtualAddress: 0x{section.VirtualAddress:x}')
            self.tree.insert(section_item, 'end', text=f'VirtualSize: 0x{section.Misc_VirtualSize:x}')
            self.tree.insert(section_item, 'end', text=f'SizeOfRawData: 0x{section.SizeOfRawData:x}')


class ProgressDialog:
    """Progress dialog for long operations"""

    def __init__(self, parent, title="Processing"):
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        self.window.geometry("400x150")
        self.window.transient(parent)
        self.window.grab_set()

        # Center window
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.window.winfo_screenheight() // 2) - (150 // 2)
        self.window.geometry(f"+{x}+{y}")

        # Label
        self.label = tk.Label(self.window, text="Processing...", font=('Arial', 10))
        self.label.pack(pady=20)

        # Progress bar
        self.progress = ttk.Progressbar(self.window, mode='indeterminate', length=300)
        self.progress.pack(pady=10)
        self.progress.start()

        # Status label
        self.status_label = tk.Label(self.window, text="", font=('Arial', 8))
        self.status_label.pack(pady=5)

    def update_status(self, text):
        """Update status text"""
        self.status_label.config(text=text)
        self.window.update()

    def close(self):
        """Close dialog"""
        self.progress.stop()
        self.window.destroy()


class SearchDialog:
    """Search dialog for finding strings/bytes"""

    def __init__(self, parent, search_callback):
        self.window = tk.Toplevel(parent)
        self.window.title("Search")
        self.window.geometry("500x200")
        self.search_callback = search_callback

        # Search type
        tk.Label(self.window, text="Search Type:").pack(pady=10)

        self.search_type = tk.StringVar(value="string")
        tk.Radiobutton(self.window, text="String", variable=self.search_type,
                      value="string").pack()
        tk.Radiobutton(self.window, text="Hex Bytes", variable=self.search_type,
                      value="hex").pack()

        # Search entry
        tk.Label(self.window, text="Search for:").pack(pady=5)
        self.search_entry = tk.Entry(self.window, width=60)
        self.search_entry.pack(pady=5)

        # Buttons
        button_frame = tk.Frame(self.window)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Search", command=self.do_search).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Close", command=self.window.destroy).pack(side=tk.LEFT, padx=5)

    def do_search(self):
        """Perform search"""
        query = self.search_entry.get()
        search_type = self.search_type.get()
        self.search_callback(query, search_type)


class CompareDialog:
    """File comparison dialog"""

    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Compare Files")
        self.window.geometry("600x400")

        tk.Label(self.window, text="File Comparison - Coming Soon",
                font=('Arial', 14)).pack(pady=20)

        tk.Label(self.window, text="This feature will allow you to:\n" +
                "• Compare two executable files\n" +
                "• Show differences in structure\n" +
                "• Compare imports/exports\n" +
                "• Highlight code differences",
                justify=tk.LEFT).pack(pady=20)

        tk.Button(self.window, text="Close", command=self.window.destroy).pack(pady=10)
