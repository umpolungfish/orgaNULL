"""
OrgaNULL - Binary Packer with Cellular Automaton Obfuscation
Main package initialization
"""

# Import main functionality
from .organull import pack_binary
from . import ca_engine
from . import crypto_engine

__version__ = "1.0.0"
__author__ = "marlboros"
__description__ = "A binary packer using Cellular Automata for obfuscation"