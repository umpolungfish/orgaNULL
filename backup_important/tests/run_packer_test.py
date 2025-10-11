#!/usr/bin/env python3
"""
Simple test script to run the packer on our test binary.
"""

import sys
import os

# Add the ca_packer directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ca_packer import packer

def main():
    input_path = os.path.join(os.path.dirname(__file__), 'test_target')
    output_path = os.path.join(os.path.dirname(__file__), 'test_target_packed')

    if not os.path.exists(input_path):
        print(f"Error: Test binary not found at {input_path}")
        sys.exit(1)

    try:
        print(f"Packing '{input_path}' -> '{output_path}'")
        # Pack with debug stub to get more information
        packer.pack_binary(input_path, output_path, debug_stub=True)
        print("Packing completed successfully.")
        
        # Try to run the packed binary
        print("Running packed binary...")
        import subprocess
        result = subprocess.run([output_path], capture_output=True, text=True)
        if result.returncode == 0:
            print("Packed binary executed successfully!")
            print("Output:", result.stdout)
        else:
            print("Packed binary failed to execute.")
            print("Exit code:", result.returncode)
            print("Stderr:", result.stderr)
            print("Stdout:", result.stdout)
            sys.exit(1)
    except Exception as e:
        print(f"Error during packing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()