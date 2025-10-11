#!/usr/bin/env python3

# Test the dynamic base calculation
# We know:
# - %r8 points to the parameter area (0x64012 in the packed binary)
# - Stub RVA is 0x64000
# - Parameter area offset from stub start is 0x12

r8 = 0x64012  # Runtime address of parameter area
stub_rva = 0x64000  # RVA of stub section
param_area_offset = 0x12  # Offset of parameter area from stub start

print(f"%r8 (runtime address of parameter area): 0x{r8:x}")
print(f"Stub RVA: 0x{stub_rva:x}")
print(f"Parameter area offset: 0x{param_area_offset:x}")

# Calculate dynamic base:
# r9 = stub_rva + param_area_offset = 0x64000 + 0x12 = 0x64012
r9 = stub_rva + param_area_offset
print(f"r9 (RVA of parameter area): 0x{r9:x}")

# r10 = r8 - r9 = 0x64012 - 0x64012 = 0
r10 = r8 - r9
print(f"r10 (dynamic base address): 0x{r10:x}")

# This seems correct. The dynamic base should be 0, which means the binary is loaded at its preferred address.
# Let's verify this makes sense by checking if adding the dynamic base to the payload RVA gives the correct runtime address.

payload_rva = 0xa5000
payload_runtime_addr = r10 + payload_rva
print(f"Payload RVA: 0x{payload_rva:x}")
print(f"Payload runtime address: 0x{payload_runtime_addr:x}")

# This should be 0 + 0xa5000 = 0xa5000, which seems correct.