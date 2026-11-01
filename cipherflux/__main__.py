"""
CipherFlux package entry point: enables running `python -m cipherflux`.
"""
import sys
from cipherflux.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
