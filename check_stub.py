#!/usr/bin/env python3
import lief
import sys

# Load the packed binary
binary = lief.parse("/home/mrnob0dy666/greenbay/packed_ls_test_fixed5")

# Print information about the .stub section
stub_section = None
for section in binary.sections:
    if section.name == ".stub":
        stub_section = section
        break

if stub_section:
    print(f".stub section:")
    print(f"  RVA: 0x{stub_section.virtual_address:x}")
    print(f"  Size: 0x{stub_section.size:x}")
    print(f"  Content size: {len(stub_section.content)}")
    
    # Check if the section has the expected content
    content = bytes(stub_section.content)
    
    # Check the first few bytes (should be the _start code)
    print(f"  First 16 bytes: {content[:16].hex()}")
    
    # Check the parameter area (should start at offset 0x12)
    param_offset = 0x12
    if len(content) > param_offset + 32:
        print(f"  Parameter area (at offset 0x{param_offset:x}): {content[param_offset:param_offset+32].hex()}")
    
    # Check the payload RVA (should be at offset 0x12 + 0x30 = 0x42)
    payload_rva_offset = 0x12 + 0x30
    if len(content) > payload_rva_offset + 8:
        payload_rva_bytes = content[payload_rva_offset:payload_rva_offset+8]
        payload_rva = int.from_bytes(payload_rva_bytes, 'little')
        print(f"  Payload RVA (at offset 0x{payload_rva_offset:x}): 0x{payload_rva:x} ({payload_rva_bytes.hex()})")
    
    # Check the stub RVA (should be at offset 0x12 + 0x40 = 0x52)
    stub_rva_offset = 0x12 + 0x40
    if len(content) > stub_rva_offset + 8:
        stub_rva_bytes = content[stub_rva_offset:stub_rva_offset+8]
        stub_rva = int.from_bytes(stub_rva_bytes, 'little')
        print(f"  Stub RVA (at offset 0x{stub_rva_offset:x}): 0x{stub_rva:x} ({stub_rva_bytes.hex()})")
else:
    print("No .stub section found")