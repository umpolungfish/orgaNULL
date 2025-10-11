#!/usr/bin/env python3

# Test the payload runtime address calculation
# We know:
# - %r8 points to the parameter area (0x64012 in the packed binary)
# - Payload RVA is 0xa5000
# - Dynamic base is 0 (as calculated previously)

r8 = 0x64012  # Runtime address of parameter area
payload_rva = 0xa5000  # RVA of payload section
dynamic_base = 0  # Calculated dynamic base

print(f"%r8 (runtime address of parameter area): 0x{r8:x}")
print(f"Payload RVA: 0x{payload_rva:x}")
print(f"Dynamic base: 0x{dynamic_base:x}")

# Calculate payload runtime address:
# rsi = payload_rva + dynamic_base = 0xa5000 + 0 = 0xa5000
payload_runtime_addr = payload_rva + dynamic_base
print(f"Payload runtime address: 0x{payload_runtime_addr:x}")

# This should be correct.