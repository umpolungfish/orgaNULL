# OrgaNULL - Binary Packer with Cellular Automaton Obfuscation

OrgaNULL is a binary packer that combines modern cryptographic techniques with cellular automaton-based obfuscation to create heavily obfuscated executables. \
This tool is designed for advanced reverse engineering protection, malware research, and binary obfuscation experimentation.

## Features

- **Dual-Layer Obfuscation**: Combines ChaCha20 encryption with Cellular Automaton (Rule 30) masking for enhanced protection
- **Pure Assembly Unpacking Stub**: Optimized x86-64 assembly code for unpacking operations
- **In-Memory Execution**: Executes original binaries directly from memory using `memfd_create` and `fexecve`
- **Anti-Debugging Protection**: Includes ptrace-based anti-debugging techniques to prevent analysis
- **Cross-Platform Support**: Works with both ELF and PE binary formats
- **Position Independent Code**: Ensures compatibility with ASLR (Address Space Layout Randomization)

## Directory Structure

- `organull/` - Core implementation files
- `tests/` - Comprehensive test suite
- `archive/` - Historical development files and intermediate implementations
- `backup_important/` - Backup of important project files
- `requirements.txt` - Python dependencies
- `README.md` - Project documentation

## Core Components

The core implementation consists of:

1. `organull/organull.py` - Main packer executable and API
2. `organull/ca_engine.py` - Cellular automaton engine (Rule 30) for mask generation
3. `organull/crypto_engine.py` - ChaCha20 encryption/decryption engine
4. `organull/complete_unpacking_stub.s` - Pure assembly unpacking stub in x86-64
5. `organull/compile_complete_unpacking_stub.py` - Assembly compilation script
6. `organull/__init__.py` - Package initialization and API exports

## Technical Details

### Cellular Automaton (CA) Engine
- Implements Rule 30 cellular automaton for pseudo-random mask generation
- Each 32-byte block of encrypted payload is masked with unique CA-generated randomness
- Block index is XORed with key material to ensure unique masks per block
- Configurable number of evolution steps (default: 100)

### Crypto Engine
- ChaCha20 stream cipher for payload encryption/decryption
- 256-bit encryption keys with 96-bit nonces
- Zero-padding for block alignment

### Assembly Stub
- Written entirely in x86-64 assembly
- Implements CA evolution algorithm in assembly
- Performs ChaCha20 decryption in assembly
- Dynamic base address calculation for ASLR compatibility
- Anti-debugging checks using ptrace
- In-memory execution using memfd_create and fexecve

## Installation

1. Clone the repository
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface
The main program can be run directly as a command:

```bash
python3 organull/organull.py <input_binary> <output_packed_binary>
```

### Command Line Options
- `--ca-steps N`: Specify number of CA evolution steps (default: 100)
- `--debug-stub`: Compile unpacking stub with debug messages

### Example Usage
```bash
# Basic packing
python3 organull/organull.py ./my_binary ./my_binary_packed

# Packing with custom CA steps
python3 organull/organull.py ./my_binary ./my_binary_packed --ca-steps 200

# Packing with debug stub enabled
python3 organull/organull.py ./my_binary ./my_binary_packed --debug-stub
```

### Python API
You can also use OrgaNULL as a Python library:

```python
from organull import pack_binary

# Pack a binary with default settings
pack_binary("input_binary", "packed_binary")

# Pack with debug stub
pack_binary("input_binary", "packed_binary", debug_stub=True)
```

## Requirements

- Python 3.7+
- LIEF library (for binary manipulation)
- Cryptography library (for ChaCha20)
- GCC toolchain (for assembly compilation)
- Linux with support for memfd_create and fexecve syscalls

Install dependencies with:
```bash
pip install -r requirements.txt
```

## Testing

The project includes a comprehensive test suite:

```bash
# Run the main integration test
python3 tests/run_packer_test.py

# Run unit tests
python3 tests/test_ca_engine.py
python3 tests/test_crypto_engine.py

# Run all tests
python -m unittest discover tests/
```

## Security Considerations

### Strengths
- Strong encryption with ChaCha20
- Additional CA-based obfuscation layer
- Assembly-based unpacking makes analysis difficult
- In-memory execution avoids disk artifacts
- Anti-debugging protections

### Limitations
- Not suitable for production security applications
- Assembly stub complexity may cause compatibility issues
- Only works on x86-64 Linux systems
- Large overhead in packed binary size

## Development

### Architecture Overview
1. Input binary is loaded and analyzed
2. Payload is extracted and encrypted with ChaCha20
3. CA-based masks are generated and applied to encrypted payload
4. Assembly unpacking stub is compiled and embedded
5. Payload and stub are integrated into new binary
6. Entry point is adjusted to point to stub

### Code Structure
- Python components handle high-level logic and binary manipulation
- Assembly stub handles low-level unpacking in x86-64
- Configuration and parameters are embedded into the stub

## Contributing

This project is maintained as a research and educational tool for binary obfuscation techniques. Contributions should focus on:
- Improving the CA engine
- Adding new obfuscation techniques
- Enhancing the assembly stub
- Improving compatibility across different binary formats

## Unlicense

This project is unlicensed

## Acknowledgments

boredom, compounds, a restless mind