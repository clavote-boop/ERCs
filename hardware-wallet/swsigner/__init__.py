"""swsigner — Phase-0 software proof of the Clavote Signer architecture.

Zero third-party dependencies (Python stdlib only; one vendored file,
vendor/ripemd160.py, MIT, Pieter Wuille). See docs/ARCHITECTURE.md.

This is a specification-by-example and test oracle for future firmware.
It is NOT a custody product: no constant-time guarantees, no
side-channel resistance, runs on a general-purpose OS.
"""

__version__ = "0.1.0"
