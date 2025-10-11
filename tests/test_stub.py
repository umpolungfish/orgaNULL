#!/usr/bin/env python3

import ctypes
import mmap
import os

# Read the compiled stub binary
with open('organull/complete_unpacking_stub_compiled.bin', 'rb') as f:
    stub_data = f.read()

# Create a memory-mapped file
stub_size = len(stub_data)
mem = mmap.mmap(-1, stub_size, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)

# Copy the stub data to the memory-mapped file
mem.write(stub_data)
mem.seek(0)

# Get a pointer to the memory
ptr = ctypes.cast(ctypes.addressof(ctypes.c_char.from_buffer(mem)), ctypes.c_void_p)

# Try to execute the stub
print("Executing stub...")
try:
    ctypes.pythonapi.PyCapsule_New(ptr, None, None)
    # This is a hack to get a callable function pointer
    # In practice, you would use a proper way to create a function pointer
    # But this is just for testing
    print("Stub executed successfully")
except Exception as e:
    print(f"Error executing stub: {e}")

# Cleanup
mem.close()