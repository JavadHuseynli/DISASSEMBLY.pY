#!/usr/bin/env python3
"""
Test script to verify EXE Analyzer installation
"""

import sys

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    print("-" * 50)

    tests = [
        ("tkinter", "GUI framework"),
        ("pefile", "PE file parsing"),
        ("capstone", "Disassembly engine"),
        ("dnfile", ".NET file support")
    ]

    failed = []

    for module_name, description in tests:
        try:
            if module_name == "tkinter":
                import tkinter
            elif module_name == "pefile":
                import pefile
            elif module_name == "capstone":
                import capstone
            elif module_name == "dnfile":
                import dnfile

            print(f"✓ {module_name:15s} - {description:30s} [OK]")
        except ImportError as e:
            print(f"✗ {module_name:15s} - {description:30s} [FAILED]")
            failed.append((module_name, str(e)))

    print("-" * 50)

    if failed:
        print("\n❌ Some dependencies are missing:\n")
        for module, error in failed:
            print(f"  {module}: {error}")
        print("\nInstall missing dependencies:")
        print("  pip install -r requirements.txt")
        return False
    else:
        print("\n✅ All dependencies installed successfully!")
        return True


def test_versions():
    """Show versions of installed packages"""
    print("\nInstalled Versions:")
    print("-" * 50)

    try:
        import pefile
        print(f"pefile:   {pefile.__version__ if hasattr(pefile, '__version__') else 'unknown'}")
    except:
        pass

    try:
        import capstone
        print(f"capstone: {capstone.__version__ if hasattr(capstone, '__version__') else 'unknown'}")
    except:
        pass

    try:
        import dnfile
        print(f"dnfile:   {dnfile.__version__ if hasattr(dnfile, '__version__') else 'unknown'}")
    except:
        pass

    print("-" * 50)


def test_capstone_architecture():
    """Test Capstone architecture support"""
    print("\nTesting Capstone architectures:")
    print("-" * 50)

    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

        architectures = [
            (CS_ARCH_X86, CS_MODE_32, "x86 (32-bit)"),
            (CS_ARCH_X86, CS_MODE_64, "x86-64 (64-bit)"),
        ]

        for arch, mode, name in architectures:
            try:
                md = Cs(arch, mode)
                print(f"✓ {name:20s} [Supported]")
            except Exception as e:
                print(f"✗ {name:20s} [Error: {e}]")

    except Exception as e:
        print(f"Error testing Capstone: {e}")

    print("-" * 50)


def test_gui():
    """Test if GUI can be initialized"""
    print("\nTesting GUI initialization:")
    print("-" * 50)

    try:
        import tkinter as tk

        # Try to create a window
        root = tk.Tk()
        root.withdraw()  # Hide the window

        print("✓ Tkinter GUI framework is working")

        # Test if we can create basic widgets
        label = tk.Label(root, text="Test")
        button = tk.Button(root, text="Test")
        text = tk.Text(root)

        print("✓ Basic widgets can be created")

        root.destroy()
        print("✓ GUI test passed")

    except Exception as e:
        print(f"✗ GUI test failed: {e}")
        print("  Note: GUI may not work in headless environments")

    print("-" * 50)


def main():
    """Run all tests"""
    print("=" * 50)
    print("EXE Analyzer - Installation Test")
    print("=" * 50)
    print()

    # Test Python version
    print(f"Python version: {sys.version}")
    print()

    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        return False

    # Run tests
    imports_ok = test_imports()
    print()

    if imports_ok:
        test_versions()
        print()
        test_capstone_architecture()
        print()
        test_gui()

    print()
    print("=" * 50)

    if imports_ok:
        print("✅ Installation test completed successfully!")
        print()
        print("You can now run the application:")
        print("  python main.py")
    else:
        print("❌ Installation test failed")
        print()
        print("Please install missing dependencies:")
        print("  pip install -r requirements.txt")

    print("=" * 50)

    return imports_ok


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
