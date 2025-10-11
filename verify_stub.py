#!/usr/bin/env python3
import lief

# Load the packed binary
binary = lief.parse("/home/mrnob0dy666/greenbay/packed_ls_test_fixed6")

# Find the .stub section
stub_section = None
for section in binary.sections:
    if section.name == ".stub":
        stub_section = section
        break

if not stub_section:
    print("No .stub section found")
    exit(1)

print(f".stub section RVA: 0x{stub_section.virtual_address:x}")
print(f".stub section size: 0x{stub_section.size:x}")

# Get the content of the stub section
content = bytes(stub_section.content)

# Check the start of the stub
print(f"First 16 bytes: {content[:16].hex()}")

# Find main_code_start in the disassembly
# We know it should be after the parameter area
# Parameter area starts at offset 0x12 and is 0x48 bytes long
# So main_code_start should be around offset 0x12 + 0x48 = 0x5a

param_area_start = 0x12
param_area_size = 0x48
main_code_start_offset = param_area_start + param_area_size

print(f"Parameter area: 0x{param_area_start:x} - 0x{param_area_start + param_area_size:x}")
print(f"Expected main_code_start offset: 0x{main_code_start_offset:x}")

# Check if there's an instruction at the expected offset
if len(content) > main_code_start_offset + 4:
    instruction = content[main_code_start_offset:main_code_start_offset+4]
    print(f"Instruction at 0x{main_code_start_offset:x}: {instruction.hex()}")
    
    # Check if it's the expected mov instruction: 4d 8b 48 40
    if instruction == b'\x4d\x8b\x48\x40':
        print("Found expected mov instruction at main_code_start")
    else:
        print(f"Unexpected instruction at main_code_start: {instruction.hex()}")
else:
    print("Not enough content to check main_code_start")

# Check the parameter values
payload_rva_offset = param_area_start + 0x30  # 0x12 + 0x30 = 0x42
payload_size_offset = param_area_start + 0x38  # 0x12 + 0x38 = 0x4a
stub_rva_offset = param_area_start + 0x40      # 0x12 + 0x40 = 0x52

if len(content) > payload_rva_offset + 8:
    payload_rva = int.from_bytes(content[payload_rva_offset:payload_rva_offset+8], 'little')
    print(f"Payload RVA at 0x{payload_rva_offset:x}: 0x{payload_rva:x}")

if len(content) > payload_size_offset + 8:
    payload_size = int.from_bytes(content[payload_size_offset:payload_size_offset+8], 'little')
    print(f"Payload size at 0x{payload_size_offset:x}: 0x{payload_size:x}")

if len(content) > stub_rva_offset + 8:
    stub_rva = int.from_bytes(content[stub_rva_offset:stub_rva_offset+8], 'little')
    print(f"Stub RVA at 0x{stub_rva_offset:x}: 0x{stub_rva:x}")