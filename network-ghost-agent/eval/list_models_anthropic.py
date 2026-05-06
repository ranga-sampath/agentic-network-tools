#!/usr/bin/env python3
"""List Anthropic models available to the configured API key.

Usage:
    python eval/list_models.py
"""
import os
import re
import sys
from pathlib import Path

# Load ANTHROPIC_API_KEY from demo/config.env if not already in environment
api_key = os.environ.get("ANTHROPIC_API_KEY")
if not api_key:
    config = Path(__file__).parent.parent / "demo" / "config.env"
    for line in config.read_text().splitlines():
        m = re.match(r'ANTHROPIC_API_KEY=["\']?(.*?)["\']?\s*$', line.strip())
        if m:
            api_key = m.group(1)
            break

if not api_key:
    sys.exit("[ERROR] ANTHROPIC_API_KEY not found in environment or demo/config.env")

import anthropic  # noqa: E402

client = anthropic.Anthropic(api_key=api_key)
print("Models available on this account:")
for model in client.models.list().data:
    print(f"  {model.id}")
