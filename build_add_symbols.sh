#!/usr/bin/env bash
# Script per compilare add_symbols_standalone con PyInstaller.
# Crea un binario standalone che può essere chiamato da Ghidra.

set -e

echo "========================================="
echo "Building add_symbols standalone binary"
echo "========================================="
echo ""

# Check if uv is available
if ! command -v uv &> /dev/null; then
    echo "ERROR: uv not found"
    echo "Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Check if PyInstaller is installed
if ! python3 -c "import PyInstaller" 2>/dev/null; then
    echo "PyInstaller not found. Installing with uv..."
    uv pip install pyinstaller
fi

# Check if LIEF is installed
if ! python3 -c "import lief" 2>/dev/null; then
    echo "LIEF not found. Installing with uv..."
    uv pip install lief
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/ dist/ __pycache__/
rm -f add_symbols

# Build with PyInstaller
echo ""
echo "Building with PyInstaller..."
pyinstaller add_symbols_standalone.spec

# Check if build was successful
if [ -f "dist/add_symbols" ]; then
    echo ""
    echo "========================================="
    echo "✓ Build successful!"
    echo "========================================="
    echo ""
    echo "Binary created: dist/add_symbols"
    echo "Size: $(du -h dist/add_symbols | cut -f1)"
    echo ""
    echo "Test with:"
    echo "  ./dist/add_symbols <input.elf> <symbols.csv> <output.elf>"
    echo ""
else
    echo ""
    echo "ERROR: Build failed!"
    exit 1
fi
