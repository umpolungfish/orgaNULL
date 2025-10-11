#!/usr/bin/env python3
"""
Verification script to check that all key OrgaNULL files exist.
"""

import os
import sys

def check_file_exists(file_path):
    """Check if a file exists and print status."""
    if os.path.exists(file_path):
        print(f"✅ {os.path.basename(file_path)}")
        return True
    else:
        print(f"❌ {os.path.basename(file_path)}")
        return False

def main():
    print("OrgaNULL File Verification")
    print("=" * 40)
    
    # Get the project root directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    # Define key files to check (actual files that exist)
    key_files = [
        # Main implementation
        "organull/organull.py",
        "organull/ca_engine.py",
        "organull/crypto_engine.py",
        
        # Assembly stubs
        "organull/complete_unpacking_stub.s",
        "organull/ca_evolution_complete.s",
        "organull/chacha20_core.s",
        "organull/poly1305_core.s",
        "organull/chacha20_poly1305_combined.s",
        "organull/chacha20_poly1305_minimal.s",
        
        # Compilation and testing
        "organull/compile_complete_unpacking_stub.py",
        "organull/test_complete_packer.py",
        
        # Documentation (in root directory)
        "README.md",
        "requirements.txt",
        "ORGANULL_FINAL_SUMMARY.md",
        "ORGANULL_DEVELOPMENT_SUMMARY.md",
        "ORGANULL_TODO.md",
        "PROJECT_COMPLETION_ANNOUNCEMENT.md",
        "ORGANULL_FINAL_IMPACT.md",
        
        # Demo scripts
        "test_ca_packer.py",
        "presentation.py",
        "verify_files.py"
    ]
    
    # Check each file
    existing_files = 0
    total_files = len(key_files)
    
    for file_path in key_files:
        full_path = os.path.join(project_root, file_path)
        if check_file_exists(full_path):
            existing_files += 1
    
    print("\n" + "=" * 40)
    print(f"Files verified: {existing_files}/{total_files}")
    
    if existing_files == total_files:
        print("🎉 All key files exist!")
        return 0
    else:
        print("⚠️  Some key files are missing!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
