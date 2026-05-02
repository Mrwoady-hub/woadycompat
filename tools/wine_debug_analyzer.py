#!/usr/bin/env python3
"""
WoadyCompat Wine/Proton Debug Log Analyzer

Parses Wine debug logs and summarizes compatibility issues.

Usage:
    python3 wine_debug_analyzer.py <logfile>
    WINEDEBUG=+loaddll,+seh wine app.exe 2>&1 | python3 wine_debug_analyzer.py -

This tool extracts:
- DLLs loaded
- Missing/failed DLLs
- Warnings and errors
- First failure point
- Estimated compatibility category

Educational reference for understanding Wine internals and troubleshooting.
"""

import sys
import re
from collections import defaultdict
from datetime import datetime


class WineDebugAnalyzer:
    """Parse and analyze Wine debug logs."""
    
    # Regex patterns
    TIMESTAMP_PATTERN = re.compile(r'^(\d{4}):(\d{4})')
    DLL_LOAD_PATTERN = re.compile(r'loaddll:.*?(\w+\.dll)', re.IGNORECASE)
    MODULE_NOT_FOUND = re.compile(
        r'(Cannot find|module not found|no such|failed to load).*?(\w+\.dll)',
        re.IGNORECASE
    )
    SEH_PATTERN = re.compile(r'seh:', re.IGNORECASE)
    ERROR_PATTERN = re.compile(r'(error|failed|exception|crash|abort)', re.IGNORECASE)
    WARNING_PATTERN = re.compile(r'(warn|warning)', re.IGNORECASE)
    ENTRY_POINT = re.compile(r'entry point.*?(\w+)', re.IGNORECASE)
    
    # Compatibility categories
    CATEGORIES = {
        'graphics': ['d3d', 'dxvk', 'vulkan', 'opengl', 'gpu', 'graphics', 'shader'],
        'networking': ['winsock', 'socket', 'http', 'dns', 'network', 'tcp', 'udp'],
        'filesystem': ['file', 'disk', 'mount', 'path', 'directory', 'drive'],
        'threading': ['thread', 'mutex', 'critical', 'sync', 'event'],
        'registry': ['registry', 'reg', 'hkey', 'wine reg'],
        'audio': ['audio', 'sound', 'wave', 'dsound', 'midi'],
        'input': ['input', 'mouse', 'keyboard', 'joystick', 'raw input'],
        'dll_loading': ['dll', 'import', 'export', 'ordinal', 'entry point'],
    }
    
    def __init__(self):
        self.dlls_loaded = set()
        self.dlls_missing = []
        self.warnings = []
        self.errors = []
        self.timestamps = []
        self.first_error_line = None
        self.first_error_content = None
        self.total_lines = 0
        self.category_keywords = defaultdict(int)
        
    def categorize_issue(self):
        """Determine the likely compatibility category."""
        # Count keyword matches
        category_scores = defaultdict(int)
        
        # Check errors and warnings for keywords
        all_content = ' '.join(self.errors + self.warnings).lower()
        
        for category, keywords in self.CATEGORIES.items():
            for keyword in keywords:
                category_scores[category] += all_content.count(keyword)
        
        # Also check missing DLLs
        for dll in self.dlls_missing:
            dll_lower = dll.lower()
            for category, keywords in self.CATEGORIES.items():
                for keyword in keywords:
                    if keyword in dll_lower:
                        category_scores[category] += 2
        
        if not category_scores:
            return "Unknown"
        
        return max(category_scores, key=category_scores.get).title()
    
    def parse_line(self, line, line_num):
        """Parse a single debug log line."""
        self.total_lines += 1
        
        # Extract timestamp if present
        ts_match = self.TIMESTAMP_PATTERN.search(line)
        if ts_match and not self.timestamps:
            self.timestamps.append((line_num, ts_match.group(0)))
        
        # Check for DLL loading
        dll_match = self.DLL_LOAD_PATTERN.search(line)
        if dll_match:
            dll_name = dll_match.group(1).lower()
            self.dlls_loaded.add(dll_name)
        
        # Check for missing modules
        missing_match = self.MODULE_NOT_FOUND.search(line)
        if missing_match:
            dll_name = missing_match.group(2).lower()
            self.dlls_missing.append(dll_name)
            if not self.first_error_line:
                self.first_error_line = line_num
                self.first_error_content = missing_match.group(0)
        
        # Check for errors
        if self.ERROR_PATTERN.search(line):
            self.errors.append(line.strip())
            if not self.first_error_line:
                self.first_error_line = line_num
                self.first_error_content = line.strip()
        
        # Check for warnings
        if self.WARNING_PATTERN.search(line):
            self.warnings.append(line.strip())
        
        # Check for SEH (Structured Exception Handling)
        if self.SEH_PATTERN.search(line):
            self.errors.append(f"SEH: {line.strip()}")
            if not self.first_error_line:
                self.first_error_line = line_num
                self.first_error_content = line.strip()
    
    def parse_log(self, lines):
        """Parse a log from an iterable of lines."""
        for line_num, line in enumerate(lines, 1):
            self.parse_line(line, line_num)
    
    def summary(self):
        """Generate a formatted summary."""
        output = []
        output.append("\n" + "=" * 70)
        output.append("  WoadyCompat Wine/Proton Debug Log Analyzer")
        output.append("=" * 70)
        
        output.append(f"\nTotal lines: {self.total_lines}")
        
        # DLLs loaded
        output.append(f"\nDLLs Loaded: {len(self.dlls_loaded)}")
        if self.dlls_loaded:
            sorted_dlls = sorted(self.dlls_loaded)
            for i, dll in enumerate(sorted_dlls[:10]):
                prefix = "├── " if i < 9 else "└── "
                output.append(f"  {prefix}{dll}")
            if len(sorted_dlls) > 10:
                output.append(f"  └── ... and {len(sorted_dlls) - 10} more")
        
        # Missing DLLs
        if self.dlls_missing:
            output.append(f"\nMissing DLLs: {len(set(self.dlls_missing))}")
            for dll in sorted(set(self.dlls_missing)):
                output.append(f"  ✗ {dll}")
        else:
            output.append("\nMissing DLLs: 0")
        
        # Warnings
        if self.warnings:
            output.append(f"\nWarnings: {len(self.warnings)}")
            for i, warning in enumerate(self.warnings[:5], 1):
                truncated = warning[:60] + "..." if len(warning) > 60 else warning
                output.append(f"  [{i}] {truncated}")
            if len(self.warnings) > 5:
                output.append(f"  ... and {len(self.warnings) - 5} more")
        else:
            output.append("\nWarnings: 0")
        
        # Errors
        if self.errors:
            output.append(f"\nErrors: {len(self.errors)}")
            for i, error in enumerate(self.errors[:5], 1):
                truncated = error[:60] + "..." if len(error) > 60 else error
                output.append(f"  [{i}] {truncated}")
            if len(self.errors) > 5:
                output.append(f"  ... and {len(self.errors) - 5} more")
        else:
            output.append("\nErrors: 0")
        
        # First failure
        if self.first_error_line:
            output.append(f"\nFirst Failure:")
            output.append(f"  Line: {self.first_error_line}")
            truncated = self.first_error_content[:65] + "..." if len(self.first_error_content) > 65 else self.first_error_content
            output.append(f"  {truncated}")
        
        # Category
        category = self.categorize_issue()
        output.append(f"\nEstimated Category: {category} Compatibility Issue")
        
        if category == "Graphics":
            output.append("  → Likely needs: DXVK, VKD3D, or GPU driver update")
        elif category == "Dll_loading":
            output.append("  → Likely needs: Missing dependency or DLL installation")
        elif category == "Networking":
            output.append("  → Likely needs: WINEPREFIX, network config, or DLL")
        elif category == "Filesystem":
            output.append("  → Likely needs: Path mapping or filesystem config")
        elif category == "Threading":
            output.append("  → Likely needs: Wine threading mode adjustment")
        
        output.append("\n" + "=" * 70)
        output.append("Educational reference for Wine/Proton troubleshooting")
        output.append("=" * 70 + "\n")
        
        return "\n".join(output)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: wine_debug_analyzer.py <logfile> | -")
        print("       - to read from stdin")
        sys.exit(1)
    
    analyzer = WineDebugAnalyzer()
    
    filename = sys.argv[1]
    try:
        if filename == "-":
            # Read from stdin
            lines = sys.stdin.readlines()
        else:
            # Read from file
            with open(filename, 'r', errors='replace') as f:
                lines = f.readlines()
        
        analyzer.parse_log(lines)
        print(analyzer.summary())
    
    except FileNotFoundError:
        print(f"Error: File not found: {filename}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
