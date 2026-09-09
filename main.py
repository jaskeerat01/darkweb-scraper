#!/usr/bin/env python3
import sys
from pathlib import Path

# Insert src directory to path if launched directly from project root
SRC_PATH = Path(__file__).resolve().parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

import asyncio
from scraper.__main__ import main

if __name__ == "__main__":
    asyncio.run(main())